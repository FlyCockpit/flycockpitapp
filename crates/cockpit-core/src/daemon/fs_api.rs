use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex as StdMutex;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, UNIX_EPOCH};

use base64::Engine as _;
use ignore::Match;
use uuid::Uuid;

use crate::daemon::principal::ClientPrincipal;
use crate::daemon::proto::{
    ErrorCode, ErrorPayload, FsEntry, FsEntryKind, FsReadKind, GitReadSource,
    GitReviewSourceResult, GitStatusEntry, Response,
};
use crate::daemon::server::DaemonContext;

const FS_LIST_ENTRY_CAP: usize = 1_000;
const GIT_REVIEW_PR_REFERENCE_BYTE_CAP: usize = 256;
const REMOTE_FILE_AGENT: &str = "remote-project-files";
const SETTINGS_CAPABILITY_TTL: Duration = Duration::from_secs(30 * 60);
const SETTINGS_CAPABILITY_GLOBAL_CAP: usize = 256;
const SETTINGS_CAPABILITY_OWNER_CAP: usize = 32;

#[derive(Clone)]
struct SettingsCapability {
    owner: String,
    snapshot_session_id: String,
    root: PathBuf,
    target: PathBuf,
    kind: cockpit_proto::CockpitConfigLayer,
    revision: String,
    raw_revision: String,
    identity: Option<cockpit_config::config::TerminalIngressFileIdentity>,
    denylist_ids: Vec<String>,
    /// Exact values replaced by opaque per-occurrence placeholders in the
    /// typed owner projection. These bytes never cross the daemon boundary.
    redacted_occurrences: std::collections::HashMap<String, RedactedSettingOccurrence>,
    expires_at: Instant,
}

#[derive(Clone)]
struct RedactedSettingOccurrence {
    original: String,
    /// RFC 6901 JSON pointer in the typed projection. A token is valid only at
    /// this exact occurrence; equal secret values still receive distinct
    /// tokens and entries.
    pointer: String,
}

fn settings_capabilities() -> &'static Mutex<std::collections::HashMap<Uuid, SettingsCapability>> {
    static CAPS: OnceLock<Mutex<std::collections::HashMap<Uuid, SettingsCapability>>> =
        OnceLock::new();
    CAPS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

pub async fn fs_list(
    ctx: Arc<DaemonContext>,
    principal: ClientPrincipal,
    project_root: String,
    path: String,
    show_hidden: bool,
) -> Result<Response, ErrorPayload> {
    join_fs_handler(
        "fs_list",
        tokio::task::spawn_blocking(move || {
            fs_list_blocking(&ctx, &principal, &project_root, &path, show_hidden)
        }),
    )
    .await
}

pub(crate) fn fs_list_blocking(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    project_root: &str,
    path: &str,
    show_hidden: bool,
) -> Result<Response, ErrorPayload> {
    let root = canonical_project_root(project_root)?;
    let dir = resolve_existing_path(&root, path)?;
    if !dir.is_dir() {
        return Err(bad_request(format!("`{path}` is not a directory")));
    }

    let mut entries = Vec::new();
    let mut truncated = false;
    for entry in std::fs::read_dir(&dir).map_err(internal)? {
        let entry = entry.map_err(internal)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !show_hidden && name.starts_with('.') {
            continue;
        }
        if entries.len() >= FS_LIST_ENTRY_CAP {
            truncated = true;
            break;
        }
        entries.push(entry_to_wire(ctx, principal, &root, entry.path(), name)?);
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Response::FsList { entries, truncated })
}

pub async fn fs_stat(
    ctx: Arc<DaemonContext>,
    principal: ClientPrincipal,
    project_root: String,
    path: String,
) -> Result<Response, ErrorPayload> {
    join_fs_handler(
        "fs_stat",
        tokio::task::spawn_blocking(move || {
            fs_stat_blocking(&ctx, &principal, &project_root, &path)
        }),
    )
    .await
}

pub(crate) fn fs_stat_blocking(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    project_root: &str,
    path: &str,
) -> Result<Response, ErrorPayload> {
    let root = canonical_project_root(project_root)?;
    let resolved = resolve_existing_path(&root, path)?;
    let name = resolved
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_string());
    let entry = entry_to_wire(ctx, principal, &root, resolved, name)?;
    Ok(Response::FsStat { entry })
}

pub async fn fs_read(
    ctx: Arc<DaemonContext>,
    principal: ClientPrincipal,
    project_root: String,
    path: String,
    wants_base64: bool,
) -> Result<Response, ErrorPayload> {
    join_fs_handler(
        "fs_read",
        tokio::task::spawn_blocking(move || {
            fs_read_sync(&ctx, &principal, &project_root, &path, wants_base64)
        }),
    )
    .await
}

pub(crate) fn fs_read_sync(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    project_root: &str,
    path: &str,
    wants_base64: bool,
) -> Result<Response, ErrorPayload> {
    let root = canonical_project_root(project_root)?;
    let resolved = resolve_existing_path(&root, path)?;
    if resolved.is_dir() {
        return Err(bad_request(format!("`{path}` is a directory")));
    }
    ensure_read_allowed(ctx, principal, &root, &resolved)?;
    #[cfg(test)]
    apply_fs_read_panic_for_test(&resolved);
    #[cfg(test)]
    apply_fs_read_block_for_test(&resolved);

    let limits = crate::resource_limits::ResourceLimits::defaults();
    let prefixed = crate::resource_limits::read_for_fs_read(&resolved).map_err(resource_limit)?;
    let hash = crate::resource_limits::sha256_hex_array(&prefixed.digest);
    let binary = crate::tools::common::looks_binary(&prefixed.prefix);
    let kind = read_kind_for_path(&resolved, binary);
    let total = usize::try_from(prefixed.len).unwrap_or(usize::MAX);
    if binary || wants_base64 {
        if !wants_base64 && !matches!(kind, FsReadKind::Image) {
            return Ok(Response::FsRead {
                content: None,
                hash,
                truncated: total > limits.fs_read_binary_bytes,
                kind,
            });
        }
        let cap = limits.fs_read_binary_bytes.min(prefixed.prefix.len());
        let truncated = total > cap;
        let content = base64::engine::general_purpose::STANDARD.encode(&prefixed.prefix[..cap]);
        return Ok(Response::FsRead {
            content: Some(content),
            hash,
            truncated,
            kind,
        });
    }
    let text = String::from_utf8_lossy(&prefixed.prefix).into_owned();
    let cap =
        cockpit_host::text::floor_char_boundary(&text, limits.fs_read_text_bytes.min(text.len()));
    let truncated = total > cap;
    Ok(Response::FsRead {
        content: Some(text[..cap].to_string()),
        hash,
        truncated,
        kind: FsReadKind::Text,
    })
}

#[cfg(test)]
struct FsReadBlockHook {
    entered: tokio::sync::oneshot::Sender<()>,
    release: Arc<(StdMutex<bool>, std::sync::Condvar)>,
}

#[cfg(test)]
fn fs_read_block_hooks() -> &'static StdMutex<std::collections::HashMap<PathBuf, FsReadBlockHook>> {
    static HOOKS: OnceLock<StdMutex<std::collections::HashMap<PathBuf, FsReadBlockHook>>> =
        OnceLock::new();
    HOOKS.get_or_init(|| StdMutex::new(std::collections::HashMap::new()))
}

#[cfg(test)]
fn fs_read_panic_hooks() -> &'static StdMutex<std::collections::HashSet<PathBuf>> {
    static HOOKS: OnceLock<StdMutex<std::collections::HashSet<PathBuf>>> = OnceLock::new();
    HOOKS.get_or_init(|| StdMutex::new(std::collections::HashSet::new()))
}

#[cfg(test)]
pub(crate) fn set_fs_read_block_for_test(
    path: PathBuf,
    entered: tokio::sync::oneshot::Sender<()>,
    release: Arc<(StdMutex<bool>, std::sync::Condvar)>,
) {
    fs_read_block_hooks()
        .lock()
        .unwrap()
        .insert(path, FsReadBlockHook { entered, release });
}

#[cfg(test)]
pub(crate) fn set_fs_read_panic_for_test(path: PathBuf) {
    fs_read_panic_hooks().lock().unwrap().insert(path);
}

#[cfg(test)]
fn apply_fs_read_panic_for_test(path: &Path) {
    if fs_read_panic_hooks().lock().unwrap().remove(path) {
        panic!("fs_read blocking body panic");
    }
}

#[cfg(test)]
fn apply_fs_read_block_for_test(path: &Path) {
    let hook = fs_read_block_hooks().lock().unwrap().remove(path);
    let Some(FsReadBlockHook { entered, release }) = hook else {
        return;
    };
    let _ = entered.send(());
    let (lock, cvar) = &*release;
    let mut released = lock.lock().unwrap();
    while !*released {
        released = cvar.wait(released).unwrap();
    }
}

pub async fn fs_write(
    ctx: Arc<DaemonContext>,
    project_root: String,
    path: String,
    content: String,
    base_hash: Option<String>,
) -> Result<Response, ErrorPayload> {
    join_fs_handler(
        "fs_write",
        tokio::task::spawn_blocking(move || {
            fs_write_sync(&ctx, &project_root, &path, &content, base_hash)
        }),
    )
    .await
}

/// Persist a rendered extended config layer through the daemon-owned config
/// mutation boundary. Unlike generic FsWrite this reloads and hashes the
/// config while holding the cross-process config lock, then commits atomically.
pub async fn save_extended_config(
    project_root: String,
    path: String,
    content: String,
    base_hash: Option<String>,
) -> Result<Response, ErrorPayload> {
    join_fs_handler(
        "save_extended_config",
        tokio::task::spawn_blocking(move || {
            save_extended_config_sync(&project_root, &path, &content, base_hash)
        }),
    )
    .await
}

/// Return every daemon-discovered settings layer. A request rooted at the
/// canonical global config directory is deliberately a global-only snapshot;
/// it never consults workspace trust or workspace-selected layers. Every
/// other request remains bound to a trusted workspace root.
pub async fn get_extended_config_snapshot(
    ctx: &crate::daemon::server::DaemonContext,
    project_root: String,
    owner: String,
    snapshot_session_id: String,
) -> Result<Response, ErrorPayload> {
    let root = settings_snapshot_root(ctx, &project_root).await?;
    let redaction = ctx.current_global_redaction();
    join_fs_handler(
        "get_extended_config_snapshot",
        tokio::task::spawn_blocking(move || {
            let mut layers = Vec::new();
            let mut pending_capabilities = Vec::new();
            let now = Instant::now();
            let discovered = discovered_settings_layers(&root)?;
            if discovered.len() > cockpit_proto::MAX_EXTENDED_CONFIG_LAYERS {
                return Err(bad_request(format!(
                    "settings inventory exceeds the {}-layer local response limit",
                    cockpit_proto::MAX_EXTENDED_CONFIG_LAYERS
                )));
            }
            for (kind, target) in discovered {
                let guard =
                    cockpit_config::config::hold_config_mutation_lock(&target).map_err(internal)?;
                let (raw, identity) = read_optional_config(&target)?;
                if raw.len() > cockpit_proto::MAX_EXTENDED_CONFIG_SOURCE_BYTES {
                    return Err(bad_request(format!(
                        "an authored settings file exceeds the {}-byte local snapshot limit; edit it outside the TUI",
                        cockpit_proto::MAX_EXTENDED_CONFIG_SOURCE_BYTES
                    )));
                }
                let raw_revision = content_hash(&raw);
                let revision = settings_revision(kind, &target, &raw_revision);
                let raw_document: serde_json::Value =
                    serde_json::from_slice(&raw).map_err(bad_request_config)?;
                let authored_paths = authored_typed_paths(&raw_document);
                let mut config: cockpit_config::config::extended::ExtendedConfig =
                    serde_json::from_slice(&raw).map_err(bad_request_config)?;
                let denylist_ids: Vec<String> = config
                    .redact
                    .denylist
                    .iter()
                    .enumerate()
                    .map(|(index, value)| denylist_occurrence_id(kind, &target, &revision, index, value))
                    .collect();
                let denylist: Vec<_> = config
                    .redact
                    .denylist
                    .iter()
                    .zip(&denylist_ids)
                    .map(|(value, id)| redacted_denylist_entry(id, value))
                    .collect();
                config.redact.denylist.clear();
                config.image_generation = config.image_generation.redacted_for_snapshot();
                let (redacted_config, redacted_occurrences) =
                    redact_extended_config_projection(config, &redaction)?;
                config = redacted_config;
                let config_projection_bytes = serde_json::to_vec(&config).map_err(internal)?;
                if target.as_os_str().as_encoded_bytes().len()
                    > cockpit_proto::MAX_AGENT_METADATA_BYTES
                    || denylist.len() > cockpit_proto::MAX_AGENT_INVENTORY_ENTRIES
                    || authored_paths.len() > cockpit_proto::MAX_AGENT_INVENTORY_ENTRIES
                    || authored_paths.iter().flatten().any(|segment| {
                        segment.len() > cockpit_proto::MAX_AGENT_METADATA_BYTES
                    })
                    || config_projection_bytes.len()
                        > cockpit_proto::MAX_EXTENDED_CONFIG_SOURCE_BYTES
                {
                    return Err(bad_request(
                        "an authored settings projection exceeds the safe local response bounds; simplify the file before opening it in the TUI",
                    ));
                }
                let id = Uuid::new_v4();
                drop(guard);
                pending_capabilities.push((
                    id,
                    SettingsCapability {
                        owner: owner.clone(),
                        snapshot_session_id: snapshot_session_id.clone(),
                        root: root.clone(),
                        target: target.clone(),
                        kind,
                        revision: revision.clone(),
                        raw_revision,
                        identity,
                        denylist_ids,
                        redacted_occurrences,
                        expires_at: now + SETTINGS_CAPABILITY_TTL,
                    },
                ));
                layers.push(cockpit_proto::ExtendedConfigLayerSnapshot {
                    layer_id: id.to_string(),
                    kind,
                    display_path: target.display().to_string(),
                    config: Box::new(config),
                    denylist,
                    revision,
                    authored_paths,
                });
            }
            let mut capabilities = settings_capabilities()
                .lock()
                .map_err(|_| internal("settings capability registry lock poisoned"))?;
            capabilities.retain(|_, cap| cap.expires_at > now);
            let belongs_to_replaced_group = |cap: &SettingsCapability| {
                cap.owner == owner
                    && cap.snapshot_session_id == snapshot_session_id
                    && cap.root == root
            };
            let owner_count = capabilities
                .values()
                .filter(|cap| cap.owner == owner && !belongs_to_replaced_group(cap))
                .count();
            if owner_count.saturating_add(pending_capabilities.len())
                > SETTINGS_CAPABILITY_OWNER_CAP
                || capabilities
                    .values()
                    .filter(|cap| !belongs_to_replaced_group(cap))
                    .count()
                    .saturating_add(pending_capabilities.len())
                    > SETTINGS_CAPABILITY_GLOBAL_CAP
            {
                return Err(conflict(
                    "settings snapshot capability capacity is exhausted; wait for an existing snapshot to expire",
                ));
            }
            // Refresh is replacement, not accumulation. Capacity is checked
            // before this exchange, so a rejected refresh leaves the prior
            // group usable; a successful one is atomic under the same lock.
            capabilities.retain(|_, cap| !belongs_to_replaced_group(cap));
            capabilities.extend(pending_capabilities);
            Ok(Response::ExtendedConfigSnapshot {
                layers,
                config_generation: crate::daemon::server::inventory::current_config_generation(),
            })
        }),
    )
    .await
}

fn authored_typed_paths(document: &serde_json::Value) -> Vec<Vec<String>> {
    fn visit(value: &serde_json::Value, path: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
        match value {
            serde_json::Value::Object(object) if !object.is_empty() => {
                for (key, value) in object {
                    path.push(key.clone());
                    visit(value, path, out);
                    path.pop();
                }
            }
            _ => out.push(path.clone()),
        }
    }
    let mut out = Vec::new();
    if let Some(object) = document.as_object() {
        for (key, value) in object {
            if cockpit_proto::ExtendedConfigField::from_json_key(key).is_none() {
                continue;
            }
            let mut path = vec![key.clone()];
            visit(value, &mut path, &mut out);
        }
    }
    out.sort();
    out
}

fn redact_extended_config_projection(
    config: cockpit_config::config::extended::ExtendedConfig,
    redaction: &crate::redact::RedactionTable,
) -> Result<
    (
        cockpit_config::config::extended::ExtendedConfig,
        std::collections::HashMap<String, RedactedSettingOccurrence>,
    ),
    ErrorPayload,
> {
    fn scrub_value(
        value: &mut serde_json::Value,
        redaction: &crate::redact::RedactionTable,
        occurrences: &mut std::collections::HashMap<String, RedactedSettingOccurrence>,
        pointer: &str,
    ) {
        match value {
            serde_json::Value::String(text) => {
                if redaction.scrub(text) != *text {
                    let placeholder =
                        format!("{SETTINGS_REDACTED_OCCURRENCE_PREFIX}{}__", Uuid::new_v4());
                    occurrences.insert(
                        placeholder.clone(),
                        RedactedSettingOccurrence {
                            original: std::mem::take(text),
                            pointer: pointer.to_string(),
                        },
                    );
                    *text = placeholder;
                }
            }
            serde_json::Value::Array(values) => {
                for (index, value) in values.iter_mut().enumerate() {
                    scrub_value(value, redaction, occurrences, &format!("{pointer}/{index}"));
                }
            }
            serde_json::Value::Object(values) => {
                for (key, value) in values.iter_mut() {
                    let key = key.replace('~', "~0").replace('/', "~1");
                    scrub_value(value, redaction, occurrences, &format!("{pointer}/{key}"));
                }
            }
            serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            }
        }
    }

    let mut value = serde_json::to_value(config).map_err(internal)?;
    let mut occurrences = std::collections::HashMap::new();
    scrub_value(&mut value, redaction, &mut occurrences, "");
    // Type-preserving deserialization is the fail-closed boundary: if a
    // secret literal occupied an enum/discriminator or otherwise made the
    // projection invalid, do not emit a subtly altered authority document.
    let config = serde_json::from_value(value).map_err(|error| {
        internal(format!(
            "redacted settings projection no longer satisfies its typed schema: {error}"
        ))
    })?;
    Ok((config, occurrences))
}

const SETTINGS_REDACTED_OCCURRENCE_PREFIX: &str = "__cockpit_redacted_setting_v1_";

fn pointer_for_path(path: &[String]) -> String {
    path.iter().fold(String::new(), |mut pointer, part| {
        pointer.push('/');
        pointer.push_str(&part.replace('~', "~0").replace('/', "~1"));
        pointer
    })
}

fn path_is_prefix(prefix: &[String], pointer: &str) -> bool {
    let encoded = pointer_for_path(prefix);
    pointer == encoded || pointer.starts_with(&format!("{encoded}/"))
}

fn restore_patch_redacted_occurrences(
    operations: &mut [cockpit_proto::ExtendedConfigPathMutation],
    occurrences: &std::collections::HashMap<String, RedactedSettingOccurrence>,
    explicitly_authorized: &std::collections::HashSet<String>,
) -> Result<(), ErrorPayload> {
    fn visit(
        value: &mut serde_json::Value,
        pointer: &str,
        occurrences: &std::collections::HashMap<String, RedactedSettingOccurrence>,
        seen: &mut std::collections::HashSet<String>,
    ) -> Result<(), ErrorPayload> {
        match value {
            serde_json::Value::String(text) => {
                if let Some(occurrence) = occurrences.get(text) {
                    if occurrence.pointer != pointer || !seen.insert(text.clone()) {
                        return Err(bad_request(
                            "redacted settings placeholder moved or was duplicated",
                        ));
                    }
                    *text = occurrence.original.clone();
                } else if text.contains(SETTINGS_REDACTED_OCCURRENCE_PREFIX) {
                    return Err(bad_request(
                        "redacted settings placeholder is unknown or altered",
                    ));
                }
            }
            serde_json::Value::Array(values) => {
                for (index, value) in values.iter_mut().enumerate() {
                    visit(value, &format!("{pointer}/{index}"), occurrences, seen)?;
                }
            }
            serde_json::Value::Object(values) => {
                for (key, value) in values.iter_mut() {
                    let key = key.replace('~', "~0").replace('/', "~1");
                    visit(value, &format!("{pointer}/{key}"), occurrences, seen)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    let mut seen = std::collections::HashSet::new();
    for operation in operations.iter_mut() {
        if let cockpit_proto::ExtendedConfigPathMutation::Set { path, value } = operation {
            visit(value, &pointer_for_path(path), occurrences, &mut seen)?;
        }
    }
    for (token, occurrence) in occurrences {
        let touched_by_parent = operations
            .iter()
            .any(|operation| path_is_prefix(operation.path(), &occurrence.pointer));
        if touched_by_parent
            && !seen.contains(token)
            && !explicitly_authorized.contains(&occurrence.pointer)
        {
            return Err(bad_request(
                "redacted setting would be removed without an exact-path Set or Unset",
            ));
        }
    }
    Ok(())
}

fn value_at_object_path<'a>(
    root: &'a serde_json::Value,
    path: &[String],
) -> Option<&'a serde_json::Value> {
    path.iter()
        .try_fold(root, |value, key| value.as_object()?.get(key))
}

fn set_object_path(
    root: &mut serde_json::Value,
    path: &[String],
    value: serde_json::Value,
) -> Result<(), ErrorPayload> {
    let (leaf, parents) = path
        .split_last()
        .ok_or_else(|| bad_request("settings path cannot be empty"))?;
    let mut cursor = root;
    for key in parents {
        if !cursor.is_object() {
            return Err(bad_request("settings path crosses a non-object value"));
        }
        cursor = cursor
            .as_object_mut()
            .expect("checked object")
            .entry(key.clone())
            .or_insert_with(|| serde_json::json!({}));
    }
    cursor
        .as_object_mut()
        .ok_or_else(|| bad_request("settings path parent is not an object"))?
        .insert(leaf.clone(), value);
    Ok(())
}

fn unset_object_path(root: &mut serde_json::Value, path: &[String]) -> Result<(), ErrorPayload> {
    let (leaf, parents) = path
        .split_last()
        .ok_or_else(|| bad_request("settings path cannot be empty"))?;
    let mut cursor = root;
    for key in parents {
        let Some(next) = cursor
            .as_object_mut()
            .and_then(|object| object.get_mut(key))
        else {
            return Ok(());
        };
        cursor = next;
    }
    if let Some(object) = cursor.as_object_mut() {
        object.remove(leaf);
        Ok(())
    } else {
        Err(bad_request("settings path parent is not an object"))
    }
}

/// Apply exact typed path operations under the daemon's config lock. Unknown
/// and secret-bearing keys outside those paths remain represented in the raw
/// document; the final typed render validates every selected path and
/// preserves the daemon-owned image registry.
pub async fn apply_extended_config_patch(
    ctx: &crate::daemon::server::DaemonContext,
    client_operation_id: String,
    request_hash: [u8; 32],
    fencing_generation: i64,
    project_root: String,
    layer_id: String,
    patch: cockpit_proto::ExtendedConfigPatch,
    expected_revision: String,
    owner: String,
    snapshot_session_id: String,
) -> Result<Response, ErrorPayload> {
    let mutation_intent_hash = patch.sanitized_intent_hash().map_err(internal)?;
    let root = settings_snapshot_root(ctx, &project_root).await?;
    let db = ctx.db.clone();
    let runtime = tokio::runtime::Handle::current();
    let settlement_owner = owner.clone();
    let settlement_operation = client_operation_id.clone();
    let mut response = join_fs_handler(
        "apply_extended_config_patch",
        tokio::task::spawn_blocking(move || {
            let id = Uuid::parse_str(&layer_id)
                .map_err(|_| conflict("settings snapshot is absent, expired, or stale"))?;
            let capability = {
                let mut caps = settings_capabilities().lock().map_err(|_| internal("settings capability registry lock poisoned"))?;
                let now = Instant::now();
                caps.retain(|_, cap| cap.expires_at > now);
                let capability = caps.get(&id).cloned()
                    .ok_or_else(|| conflict("settings snapshot is absent, expired, or stale"))?;
                if capability.owner != owner
                    || capability.snapshot_session_id != snapshot_session_id
                    || capability.root != root
                    || capability.revision != expected_revision
                {
                    return Err(conflict("settings snapshot is absent, expired, or stale"));
                }
                // One apply consumes the complete snapshot group atomically.
                // This prevents unused sibling layer capabilities from
                // outliving the authority view against which the patch was
                // authored.
                caps.retain(|_, cap| {
                    !(cap.owner == owner
                        && cap.snapshot_session_id == snapshot_session_id
                        && cap.root == root)
                });
                capability
            };
            let target = capability.target.clone();
            let _guard =
                cockpit_config::config::hold_config_mutation_lock(&target).map_err(internal)?;
            let (raw, identity) = read_optional_config(&target)?;
            let existed = identity.is_some();
            if identity != capability.identity {
                return Err(conflict("configuration file identity changed since snapshot"));
            }
            let materialize = patch.materialize;
            let current_hash = content_hash(&raw);
            if current_hash != capability.raw_revision {
                return Err(ErrorPayload {
                    code: ErrorCode::HashMismatch,
                    message: "configuration changed before patch; reload its authoritative snapshot".into(),
                });
            }
            let mut document: serde_json::Value =
                serde_json::from_slice(&raw).map_err(bad_request_config)?;
            let mut operations = patch.operations;
            let mut selected_paths = std::collections::HashSet::new();
            for operation in &operations {
                let path = operation.path();
                let Some(root_field) = path
                    .first()
                    .and_then(|key| cockpit_proto::ExtendedConfigField::from_json_key(key))
                else {
                    return Err(bad_request("settings mutation path is not owned by the typed schema"));
                };
                if root_field == cockpit_proto::ExtendedConfigField::ImageGeneration {
                    return Err(bad_request(
                        "image generation settings require the dedicated daemon API",
                    ));
                }
                if path == ["redact".to_string(), "denylist".to_string()] {
                    return Err(bad_request("redact.denylist requires its opaque occurrence API"));
                }
                if !selected_paths.insert(path.to_vec()) {
                    return Err(bad_request("a settings path may be selected exactly once"));
                }
            }
            let mut authorized_redacted_pointers: std::collections::HashSet<String> = operations
                .iter()
                .map(|operation| pointer_for_path(operation.path()))
                .collect();
            let explicit_redacted_pointers: std::collections::HashSet<String> = patch
                .redacted_mutations
                .iter()
                .map(|mutation| match mutation {
                    cockpit_proto::RedactedOccurrenceMutation::Set { pointer, .. }
                    | cockpit_proto::RedactedOccurrenceMutation::Unset { pointer } => pointer.clone(),
                })
                .collect();
            if explicit_redacted_pointers.iter().any(|pointer| {
                pointer.len() > 2_048
                    || pointer.contains('\0')
                    || !pointer.starts_with('/')
                    || pointer.contains(SETTINGS_REDACTED_OCCURRENCE_PREFIX)
            }) {
                return Err(bad_request("redacted settings pointer is invalid"));
            }
            authorized_redacted_pointers.extend(explicit_redacted_pointers);
            restore_patch_redacted_occurrences(
                &mut operations,
                &capability.redacted_occurrences,
                &authorized_redacted_pointers,
            )?;
            for operation in &operations {
                match operation {
                    cockpit_proto::ExtendedConfigPathMutation::Set { path, value } => {
                        set_object_path(&mut document, path, value.clone())?;
                    }
                    cockpit_proto::ExtendedConfigPathMutation::Unset { path } => {
                        unset_object_path(&mut document, path)?;
                    }
                }
            }
            let object = document.as_object_mut().ok_or_else(|| {
                bad_request("extended config root must be a JSON object")
            })?;
            // Removed pre-launch configuration is garbage-collected by every
            // settings save path, not only ExtendedConfigDoc::write.
            object.remove("llm_mode");
            apply_redacted_occurrence_mutations(
                object,
                patch.redacted_mutations,
                &capability.redacted_occurrences,
            )?;
            let denylist_values = apply_denylist_sequence(
                object,
                patch.denylist,
                &capability.denylist_ids,
            )?;
            let patched = serde_json::to_vec_pretty(&document).map_err(internal)?;
            let merged = cockpit_config::config::extended::render_saved_extended_config_preserving_image_generation(
                &patched,
                &raw,
            )
            .map_err(bad_request_config)?;
            let merged_document: serde_json::Value =
                serde_json::from_slice(&merged).map_err(bad_request_config)?;
            let typed_projection = serde_json::to_value(
                serde_json::from_slice::<cockpit_config::config::extended::ExtendedConfig>(&merged)
                    .map_err(bad_request_config)?,
            )
            .map_err(internal)?;
            for operation in &operations {
                match operation {
                    cockpit_proto::ExtendedConfigPathMutation::Set { path, value } => {
                        if value_at_object_path(&typed_projection, path) != Some(value) {
                            return Err(bad_request(
                                "settings Set path is not represented exactly by the typed schema",
                            ));
                        }
                    }
                    cockpit_proto::ExtendedConfigPathMutation::Unset { path } => {
                        if value_at_object_path(&merged_document, path).is_some() {
                            return Err(internal("settings Unset path remained authored after rendering"));
                        }
                    }
                }
            }
            let desired_hash = content_hash(&merged);
            let result_revision = settings_revision(capability.kind, &target, &desired_hash);
            let changed = desired_hash != current_hash || (materialize && !existed);
            let config_generation = if changed {
                crate::daemon::server::inventory::current_config_generation().saturating_add(1)
            } else {
                crate::daemon::server::inventory::current_config_generation()
            };
            let mut terminal_response = Response::ExtendedConfigSaved {
                client_operation_id: client_operation_id.clone(),
                request_hash: request_hash.iter().map(|byte| format!("{byte:02x}")).collect(),
                mutation_intent_hash,
                hash: result_revision.clone(),
                config_generation,
                layer_id: layer_id.clone(),
                layer: capability.kind,
                consumed_revision: expected_revision.clone(),
                result_revision: result_revision.clone(),
                status: cockpit_proto::ConfigCommitStatus::Committed,
                publication: cockpit_proto::ConfigPublicationStatus::Published,
                denylist: denylist_values
                    .iter()
                    .enumerate()
                    .map(|(index, (_, client_nonce, value))| cockpit_proto::CommittedDenylistEntry {
                        entry_id: denylist_occurrence_id(capability.kind, &target, &result_revision, index, value),
                        consumed_entry_id: client_nonce.is_none().then(|| denylist_values[index].0.clone()),
                        client_nonce: client_nonce.clone(),
                        display_mask: cockpit_proto::REDACTED_DENYLIST_MASK.into(),
                    })
                    .collect(),
            };
            let mut terminal_response_json =
                serde_json::to_string(&terminal_response).map_err(internal)?;
            let journal_owner = owner.clone();
            let journal_operation = client_operation_id.clone();
            let journal_root = root.to_string_lossy().into_owned();
            let journal_target = target.to_string_lossy().into_owned();
            let journal_consumed = current_hash.clone();
            let journal_intended = desired_hash.clone();
            let journal_response = terminal_response_json.clone();
            // Do not wait on the SQLite writer while holding a filesystem
            // mutation lock. Recovery is deliberately conservative if the
            // target changes in this short prepare/reacquire interval.
            drop(_guard);
            runtime.block_on(db.write(move |conn| {
                conn.execute(
                    "INSERT INTO extended_config_patch_journals
                     (owner_digest,client_operation_id,request_hash,fencing_generation,
                      project_root,target_path,consumed_content_hash,intended_content_hash,
                      terminal_response_json,created_at_unix_ms)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                    rusqlite::params![journal_owner,journal_operation,request_hash.as_slice(),fencing_generation,journal_root,journal_target,journal_consumed,journal_intended,journal_response,chrono::Utc::now().timestamp_millis()],
                )?;
                Ok(())
            })).map_err(internal)?;
            let _publication_guard =
                cockpit_config::config::hold_config_mutation_lock(&target).map_err(internal)?;
            // Re-open after durable prepare and after reacquiring the target
            // lock. This closes both external-editor and daemon-writer races.
            let (precommit, precommit_identity) = read_optional_config(&target)?;
            if precommit_identity != capability.identity
                || content_hash(&precommit) != capability.raw_revision
            {
                drop(_publication_guard);
                let abandon_owner = owner.clone();
                let abandon_operation = client_operation_id.clone();
                runtime
                    .block_on(db.write(move |conn| {
                        let deleted = conn.execute(
                            "DELETE FROM extended_config_patch_journals
                              WHERE owner_digest=?1 AND client_operation_id=?2
                                AND request_hash=?3 AND fencing_generation=?4",
                            rusqlite::params![
                                abandon_owner,
                                abandon_operation,
                                request_hash.as_slice(),
                                fencing_generation
                            ],
                        )?;
                        if deleted != 1 {
                            anyhow::bail!("typed settings recovery intent disappeared before safe abandonment");
                        }
                        Ok(())
                    }))
                    .map_err(internal)?;
                return Err(conflict(
                    "configuration target changed immediately before commit",
                ));
            }
            let published_generation = if changed {
                cockpit_config::config::write_config_bytes_atomic(&target, &merged)
                    .map_err(internal)?;
                Some(crate::daemon::server::inventory::publish_committed_config_generation())
            } else {
                None
            };
            drop(_publication_guard);
            if let Some(published) = published_generation
                && published != config_generation {
                    if let Response::ExtendedConfigSaved { config_generation, .. } = &mut terminal_response {
                        *config_generation = published;
                    }
                    terminal_response_json = serde_json::to_string(&terminal_response).map_err(internal)?;
                    let amend_owner = owner.clone();
                    let amend_operation = client_operation_id.clone();
                    let amended_response = terminal_response_json.clone();
                    runtime.block_on(db.write(move |conn| {
                        let changed = conn.execute(
                            "UPDATE extended_config_patch_journals
                                SET terminal_response_json=?3
                              WHERE owner_digest=?1 AND client_operation_id=?2",
                            rusqlite::params![amend_owner, amend_operation, amended_response],
                        )?;
                        if changed != 1 { anyhow::bail!("typed settings recovery intent disappeared before generation amendment"); }
                        Ok(())
                    })).map_err(internal)?;
                }
            Ok(terminal_response)
        }),
    )
    .await?;
    if let Err(error) = ctx.refresh_redaction_table() {
        ctx.poison_redaction_publication(&error);
        if let Response::ExtendedConfigSaved { publication, .. } = &mut response {
            *publication = cockpit_proto::ConfigPublicationStatus::Degraded;
        }
    }
    let terminal_response_json = serde_json::to_string(&response).map_err(internal)?;
    ctx.db
        .transaction(move |conn| {
            let updated = conn.execute(
                "UPDATE local_operation_receipts SET state='terminal_success',terminal_outcome_json=?5,execution_expires_at_unix_ms=NULL,updated_at_unix_ms=?6
                 WHERE owner_digest=?1 AND client_operation_id=?2 AND request_hash=?3 AND fencing_generation=?4 AND state='executing'",
                rusqlite::params![settlement_owner,settlement_operation,request_hash.as_slice(),fencing_generation,terminal_response_json,chrono::Utc::now().timestamp_millis()],
            )?;
            if updated != 1 {
                anyhow::bail!("typed settings operation lost its execution fence");
            }
            conn.execute(
                "DELETE FROM extended_config_patch_journals WHERE owner_digest=?1 AND client_operation_id=?2",
                rusqlite::params![settlement_owner, settlement_operation],
            )?;
            Ok(())
        })
        .await
        .map_err(internal)?;
    Ok(response)
}

async fn settings_snapshot_root(
    ctx: &DaemonContext,
    project_root: &str,
) -> Result<PathBuf, ErrorPayload> {
    let root = canonical_project_root(project_root)?;
    if is_global_config_root(&root)? {
        return Ok(root);
    }
    let policy = crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &root)
        .await
        .map_err(|error| ErrorPayload {
            code: ErrorCode::WorkspaceTrust,
            message: format!("workspace trust is required for settings mutation: {error:#}"),
        })?;
    if policy.mode != crate::db::workspace_trust::WorkspaceTrustMode::Trust {
        return Err(ErrorPayload {
            code: ErrorCode::WorkspaceTrust,
            message: "settings mutation requires a trusted workspace".into(),
        });
    }
    Ok(root)
}

/// Reconcile hash-only typed-settings publication intents before generic local
/// operation interruption settlement. Matching intended bytes prove the exact
/// redacted success receipt; matching consumed bytes prove publication never
/// occurred and permit a fresh snapshot/retry. Divergence remains pending.
pub(super) async fn recover_extended_config_patch_journals(
    ctx: &crate::daemon::server::DaemonContext,
    publication: crate::daemon::config_publication_recovery::PreSocketConfigPublication,
) -> Result<(), ErrorPayload> {
    type Row = (String, String, Vec<u8>, i64, String, String, String, String);
    let rows: Vec<Row> = ctx
        .db
        .read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT owner_digest,client_operation_id,request_hash,fencing_generation,
                        target_path,consumed_content_hash,intended_content_hash,terminal_response_json
                   FROM extended_config_patch_journals ORDER BY created_at_unix_ms",
            )?;
            let rows = stmt
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
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
        .map_err(internal)?;
    for (owner, operation, request_hash, fence, target, consumed, intended, response_json) in rows {
        let path = std::path::PathBuf::from(target);
        let observed_path = path.clone();
        let observed = publication.with_target(&path, move |_| {
            let (bytes, _) = read_optional_config(&observed_path)
                .map_err(|error| anyhow::anyhow!(error.message))?;
            Ok(content_hash(&bytes))
        })
        .await
        .map_err(|error| ErrorPayload {
            code: ErrorCode::Shutdown,
            message: format!("bounded typed-settings recovery could not acquire publication authority: {error:#}"),
        })?;
        let terminal = if observed == intended {
            let mut response: Response = serde_json::from_str(&response_json).map_err(internal)?;
            let generation = if intended == consumed {
                crate::daemon::server::inventory::current_config_generation()
            } else {
                crate::daemon::server::inventory::publish_committed_config_generation()
            };
            let Response::ExtendedConfigSaved {
                config_generation, ..
            } = &mut response
            else {
                return Err(internal(
                    "typed settings journal contains the wrong terminal response",
                ));
            };
            *config_generation = generation;
            Some((
                "terminal_success",
                serde_json::to_string(&response).map_err(internal)?,
            ))
        } else if observed == consumed {
            Some((
                "terminal_error",
                serde_json::to_string(&ErrorPayload {
                    code: ErrorCode::Conflict,
                    message: "typed settings publication did not occur before daemon restart; reload the authoritative snapshot and retry".into(),
                })
                .map_err(internal)?,
            ))
        } else {
            None
        };
        let Some((state, outcome)) = terminal else {
            tracing::warn!(client_operation_id = %operation, "typed settings recovery observed divergent content; settlement remains unknown");
            continue;
        };
        ctx.db
            .transaction(move |conn| {
                let updated = conn.execute(
                    "UPDATE local_operation_receipts SET state=?5,terminal_outcome_json=?6,execution_expires_at_unix_ms=NULL,updated_at_unix_ms=?7
                     WHERE owner_digest=?1 AND client_operation_id=?2 AND request_hash=?3 AND fencing_generation=?4 AND state='executing'",
                    rusqlite::params![owner,operation,request_hash,fence,state,outcome,chrono::Utc::now().timestamp_millis()],
                )?;
                if updated != 1 { anyhow::bail!("typed settings recovery lost its execution fence"); }
                conn.execute("DELETE FROM extended_config_patch_journals WHERE owner_digest=?1 AND client_operation_id=?2", rusqlite::params![owner,operation])?;
                Ok(())
            })
            .await
            .map_err(internal)?;
    }
    Ok(())
}

fn discovered_settings_layers(
    root: &Path,
) -> Result<Vec<(cockpit_proto::CockpitConfigLayer, PathBuf)>, ErrorPayload> {
    use cockpit_config::config::dirs::{CONFIG_FILE, ConfigDirKind as K};
    if is_global_config_root(root)? {
        return Ok(vec![(
            cockpit_proto::CockpitConfigLayer::HomeXdg,
            cockpit_config::config::dirs::global_config_file().map_err(internal)?,
        )]);
    }
    let mut layer_dirs = cockpit_config::config::dirs::discover_config_dirs(root);
    if let Ok(global) = cockpit_config::config::dirs::global_config_dir() {
        layer_dirs.push(cockpit_config::config::dirs::ConfigDir {
            kind: K::HomeXdg,
            path: global,
        });
    }
    layer_dirs.push(cockpit_config::config::dirs::ConfigDir {
        kind: K::MachineLocal,
        path: cockpit_config::config::dirs::local_config_dir_for(root).map_err(internal)?,
    });
    layer_dirs.push(cockpit_config::config::dirs::ConfigDir {
        kind: K::Project,
        path: root.join(".cockpit"),
    });
    let mut seen = std::collections::HashSet::new();
    Ok(layer_dirs
        .into_iter()
        .filter_map(|dir| {
            let target = dir.path.join(CONFIG_FILE);
            if !seen.insert(target.clone()) {
                return None;
            }
            let kind = match dir.kind {
                K::HomeXdg => cockpit_proto::CockpitConfigLayer::HomeXdg,
                K::MachineLocal => cockpit_proto::CockpitConfigLayer::MachineLocal,
                K::Project => cockpit_proto::CockpitConfigLayer::Project,
            };
            Some((kind, target))
        })
        .collect())
}

/// `project_root` is also the capability root for settings mutations. The
/// canonical global config directory is the one non-workspace root accepted
/// here: its config is user-owned and must remain writable without a trust
/// decision for whichever workspace happened to launch onboarding.
fn is_global_config_root(root: &Path) -> Result<bool, ErrorPayload> {
    let global = cockpit_config::config::dirs::global_config_dir().map_err(internal)?;
    let canonical_global = std::fs::canonicalize(global).map_err(internal)?;
    Ok(root == canonical_global)
}

fn read_optional_config(
    target: &Path,
) -> Result<
    (
        Vec<u8>,
        Option<cockpit_config::config::TerminalIngressFileIdentity>,
    ),
    ErrorPayload,
> {
    Ok(
        match cockpit_config::config::read_config_file_nofollow_with_identity(target)
            .map_err(internal)?
        {
            Some((bytes, identity)) => (bytes, Some(identity)),
            None => (b"{}\n".to_vec(), None),
        },
    )
}

fn denylist_occurrence_id(
    kind: cockpit_proto::CockpitConfigLayer,
    target: &Path,
    revision: &str,
    index: usize,
    value: &str,
) -> String {
    crate::daemon::authority_token::mint(
        b"settings-denylist-occurrence/v1",
        &[
            &[kind as u8],
            target.as_os_str().as_encoded_bytes(),
            revision.as_bytes(),
            &index.to_le_bytes(),
            value.as_bytes(),
        ],
    )
}

fn settings_revision(
    kind: cockpit_proto::CockpitConfigLayer,
    target: &Path,
    raw_revision: &str,
) -> String {
    crate::daemon::authority_token::mint(
        b"settings-layer-revision/v1",
        &[
            &[kind as u8],
            target.as_os_str().as_encoded_bytes(),
            raw_revision.as_bytes(),
        ],
    )
}

fn redacted_denylist_entry(id: &str, _value: &str) -> cockpit_proto::RedactedDenylistEntry {
    cockpit_proto::RedactedDenylistEntry {
        entry_id: id.to_owned(),
        display_mask: cockpit_proto::REDACTED_DENYLIST_MASK.into(),
    }
}

fn apply_denylist_sequence(
    document: &mut serde_json::Map<String, serde_json::Value>,
    desired: Vec<cockpit_proto::DesiredDenylistEntry>,
    occurrence_ids: &[String],
) -> Result<Vec<(String, Option<String>, String)>, ErrorPayload> {
    let redact = document
        .entry("redact")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or_else(|| bad_request("redact settings must be an object"))?;
    let values = redact
        .entry("denylist")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .ok_or_else(|| bad_request("redact.denylist must be an array"))?;
    let values: Vec<(String, String)> = values
        .iter()
        .zip(occurrence_ids)
        .map(|(value, id)| {
            value
                .as_str()
                .map(|value| (id.clone(), value.to_owned()))
                .ok_or_else(|| bad_request("redact.denylist entries must be strings"))
        })
        .collect::<Result<_, _>>()?;
    if values.len() != occurrence_ids.len() {
        return Err(conflict("denylist occurrences changed since snapshot"));
    }
    let by_id = values
        .iter()
        .cloned()
        .collect::<std::collections::HashMap<_, _>>();
    let mut used = std::collections::HashSet::new();
    let mut nonces = std::collections::HashSet::new();
    let mut result = Vec::with_capacity(desired.len());
    for entry in desired {
        match entry {
            cockpit_proto::DesiredDenylistEntry::Existing { entry_id } => {
                if !used.insert(entry_id.clone()) {
                    return Err(bad_request("a denylist occurrence may appear exactly once"));
                }
                let value = by_id
                    .get(&entry_id)
                    .cloned()
                    .ok_or_else(|| conflict("denylist entry changed since snapshot"))?;
                result.push((entry_id, None, value));
            }
            cockpit_proto::DesiredDenylistEntry::New {
                client_nonce,
                literal,
            } => {
                let parsed_nonce = Uuid::parse_str(&client_nonce).ok();
                if parsed_nonce
                    .as_ref()
                    .is_none_or(|nonce| nonce.to_string() != client_nonce)
                    || !nonces.insert(client_nonce.clone())
                {
                    return Err(bad_request(
                        "new denylist occurrence nonce is invalid or duplicated",
                    ));
                }
                validate_new_denylist_literal(literal.as_str())?;
                // The post-commit occurrence ID is derived only after the
                // resulting document revision is known.
                result.push((
                    String::new(),
                    Some(client_nonce),
                    literal.as_str().to_owned(),
                ));
            }
        }
    }
    redact.insert(
        "denylist".into(),
        serde_json::Value::Array(
            result
                .iter()
                .map(|(_, _, value)| serde_json::Value::String(value.clone()))
                .collect(),
        ),
    );
    Ok(result)
}

fn apply_redacted_occurrence_mutations(
    document: &mut serde_json::Map<String, serde_json::Value>,
    mutations: Vec<cockpit_proto::RedactedOccurrenceMutation>,
    occurrences: &std::collections::HashMap<String, RedactedSettingOccurrence>,
) -> Result<(), ErrorPayload> {
    fn decode(segment: &str) -> String {
        segment.replace("~1", "/").replace("~0", "~")
    }
    fn parent_mut<'a>(
        root: &'a mut serde_json::Value,
        pointer: &str,
    ) -> Result<(&'a mut serde_json::Value, String), ErrorPayload> {
        let mut segments = pointer
            .strip_prefix('/')
            .ok_or_else(|| bad_request("redacted mutation pointer must be absolute"))?
            .split('/')
            .map(decode)
            .collect::<Vec<_>>();
        let leaf = segments
            .pop()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| bad_request("redacted mutation pointer has no leaf"))?;
        let mut current = root;
        for segment in segments {
            current = match current {
                serde_json::Value::Object(object) => object
                    .get_mut(&segment)
                    .ok_or_else(|| conflict("redacted mutation parent changed"))?,
                serde_json::Value::Array(array) => array
                    .get_mut(
                        segment
                            .parse::<usize>()
                            .map_err(|_| bad_request("redacted array pointer is invalid"))?,
                    )
                    .ok_or_else(|| conflict("redacted mutation array parent changed"))?,
                _ => {
                    return Err(conflict(
                        "redacted mutation parent is no longer a container",
                    ));
                }
            };
        }
        Ok((current, leaf))
    }

    let mut seen = std::collections::HashSet::new();
    let mut root = serde_json::Value::Object(std::mem::take(document));
    for mutation in mutations {
        let pointer = match &mutation {
            cockpit_proto::RedactedOccurrenceMutation::Set { pointer, .. }
            | cockpit_proto::RedactedOccurrenceMutation::Unset { pointer } => pointer,
        };
        if !seen.insert(pointer.clone())
            || !occurrences.values().any(|entry| entry.pointer == *pointer)
        {
            return Err(bad_request(
                "redacted mutation is not bound to one snapshot occurrence",
            ));
        }
        if let cockpit_proto::RedactedOccurrenceMutation::Set { value, .. } = &mutation
            && (value.len() > 64 * 1024
                || value.as_str().contains('\0')
                || value.as_str().contains(SETTINGS_REDACTED_OCCURRENCE_PREFIX))
        {
            return Err(bad_request("redacted setting replacement is invalid"));
        }
        let (parent, leaf) = parent_mut(&mut root, pointer)?;
        match (parent, mutation) {
            (
                serde_json::Value::Object(object),
                cockpit_proto::RedactedOccurrenceMutation::Set { value, .. },
            ) => {
                object.insert(leaf, serde_json::Value::String(value.as_str().to_owned()));
            }
            (
                serde_json::Value::Object(object),
                cockpit_proto::RedactedOccurrenceMutation::Unset { .. },
            ) => {
                if object.remove(&leaf).is_none() {
                    return Err(conflict("redacted mutation target changed"));
                }
            }
            (
                serde_json::Value::Array(array),
                cockpit_proto::RedactedOccurrenceMutation::Set { value, .. },
            ) => {
                let index = leaf
                    .parse::<usize>()
                    .map_err(|_| bad_request("redacted array pointer is invalid"))?;
                let slot = array
                    .get_mut(index)
                    .ok_or_else(|| conflict("redacted mutation target changed"))?;
                *slot = serde_json::Value::String(value.as_str().to_owned());
            }
            (
                serde_json::Value::Array(array),
                cockpit_proto::RedactedOccurrenceMutation::Unset { .. },
            ) => {
                let index = leaf
                    .parse::<usize>()
                    .map_err(|_| bad_request("redacted array pointer is invalid"))?;
                if index >= array.len() {
                    return Err(conflict("redacted mutation target changed"));
                }
                array.remove(index);
            }
            _ => return Err(conflict("redacted mutation parent changed type")),
        }
    }
    *document = root.as_object_mut().expect("root remains object").clone();
    Ok(())
}

fn validate_new_denylist_literal(value: &str) -> Result<(), ErrorPayload> {
    // Align with `MAX_SENSITIVE_FRAME_BYTES` (16 KiB): the wire type
    // `SensitiveWireLiteral` enforces this cap at deserialization, so a larger
    // literal fails closed before reaching this validator.  Keeping the
    // validator at the same bound gives one consistent failure mode instead
    // of two different errors for the same logical constraint.
    if value.is_empty()
        || value.len() > cockpit_proto::MAX_SENSITIVE_FRAME_BYTES
        || value.contains('\0')
    {
        return Err(bad_request("denylist literal is invalid"));
    }
    let trimmed = value.trim();
    let legacy_mask = trimmed.starts_with("•••• (") && trimmed.ends_with(" bytes)");
    let star_mask = !trimmed.is_empty() && trimmed.bytes().all(|byte| byte == b'*');
    let bullet_mask = !trimmed.is_empty() && trimmed.chars().all(|character| character == '•');
    let numbered_legacy_mask = trimmed.starts_with("******** #")
        && trimmed.strip_prefix("******** #").is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
        });
    if trimmed == cockpit_proto::REDACTED_DENYLIST_MASK
        || legacy_mask
        || star_mask
        || bullet_mask
        || numbered_legacy_mask
    {
        return Err(bad_request(
            "redacted denylist display masks are not accepted as literals",
        ));
    }
    Ok(())
}

fn save_extended_config_sync(
    project_root: &str,
    path: &str,
    content: &str,
    base_hash: Option<String>,
) -> Result<Response, ErrorPayload> {
    let root = canonical_project_root(project_root)?;
    let target = resolve_for_write(&root, path)?;
    if target.file_name().and_then(|name| name.to_str()) != Some("config.json") {
        return Err(bad_request("extended config target must be config.json"));
    }
    let _guard = cockpit_config::config::hold_config_mutation_lock(&target).map_err(internal)?;
    // Only a genuinely-absent file is an empty config. A non-NotFound read error
    // (EACCES/EIO/EMFILE/…, over-cap, non-regular) must NOT be coerced to empty:
    // the merge would then find no on-disk `image_generation` to preserve and
    // the atomic write would WIPE the registry — the exact data loss this path
    // exists to prevent. Fail closed instead, writing nothing. The body is
    // required for the registry-preserving merge, so this lane cannot swap in
    // a streamed digest.
    let current =
        crate::resource_limits::read_existing_or_empty(&target).map_err(resource_limit)?;
    let current_hash = content_hash(&current);
    if let Some(expected) = base_hash.as_deref()
        && expected != current_hash
    {
        return Err(ErrorPayload {
            code: ErrorCode::HashMismatch,
            message: format!("configuration changed before write; current hash is {current_hash}"),
        });
    }
    // `SaveExtendedConfig` is never the authoritative writer of
    // `image_generation`: the daemon redacts the registry to the empty default
    // before the snapshot ever reaches a client, so a verbatim write of the
    // round-tripped doc would WIPE the on-disk endpoints/targets/workflows/
    // allowlist. Route the write through the merge that strips the incoming
    // (client-authored) `image_generation` and preserves the on-disk registry;
    // every other config section is taken verbatim from the incoming doc.
    let merged =
        cockpit_config::config::extended::render_saved_extended_config_preserving_image_generation(
            content.as_bytes(),
            &current,
        )
        .map_err(bad_request_config)?;
    // Reject an invalid KB trust policy before the atomic write. In
    // particular, a trust-required KB cannot persist an untrusted dream model
    // and remote KBs cannot claim a client-side-only trust guarantee.
    let merged_value: serde_json::Value =
        serde_json::from_slice(&merged).map_err(bad_request_config)?;
    let extended: cockpit_config::config::extended::ExtendedConfig =
        serde_json::from_value(merged_value).map_err(bad_request_config)?;
    // Provider bodies are layered separately from config.json. Resolve the
    // actual effective catalog instead of treating a project-only settings
    // write as if it had no trusted providers from an ambient layer.
    let provider_paths = cockpit_config::config::dirs::config_file_paths_for_load(&root);
    let providers = cockpit_config::config::providers::ConfigDoc::try_load_effective_from_paths(
        &provider_paths,
    )
    .map_err(bad_request_config)?;
    cockpit_config::config::extended::validate_knowledge_base_registry(
        &extended.knowledge_bases,
        &providers,
    )
    .map_err(|_| invalid_knowledge_base_trust_config())?;
    let desired_hash = content_hash(&merged);
    let config_generation = if desired_hash != current_hash {
        cockpit_config::config::write_config_bytes_atomic(&target, &merged).map_err(internal)?;
        crate::daemon::server::inventory::publish_committed_config_generation()
    } else {
        crate::daemon::server::inventory::current_config_generation()
    };
    Ok(Response::ExtendedConfigWritten {
        hash: desired_hash,
        config_generation,
    })
}

pub async fn fs_write_staged_remote(
    ctx: Arc<DaemonContext>,
    project_root: String,
    path: String,
    content: String,
    base_hash: Option<String>,
    operation_id: String,
) -> Result<Response, ErrorPayload> {
    join_fs_handler(
        "fs_write",
        tokio::task::spawn_blocking(move || {
            fs_write_staged_sync(
                &ctx,
                &project_root,
                &path,
                &content,
                base_hash,
                &operation_id,
            )
        }),
    )
    .await
}

pub(crate) fn fs_write_staged_sync(
    ctx: &DaemonContext,
    project_root: &str,
    path: &str,
    content: &str,
    base_hash: Option<String>,
    operation_id: &str,
) -> Result<Response, ErrorPayload> {
    use std::io::Write as _;

    let root = canonical_project_root(project_root)?;
    let target = resolve_for_write(&root, path)?;
    let locks = ctx.registry.locks();
    let _guard = locks
        .acquire_transient(&target, REMOTE_FILE_AGENT)
        .map_err(lock_conflict)?;
    let desired_hash = content_hash(content.as_bytes());
    let current_hash =
        crate::resource_limits::hash_existing_or_empty(&target).map_err(resource_limit)?;
    if current_hash == desired_hash {
        return Ok(Response::FsWrite { hash: desired_hash });
    }
    if let Some(expected) = base_hash.as_deref()
        && expected != current_hash
    {
        return Err(ErrorPayload {
            code: ErrorCode::HashMismatch,
            message: format!("file changed before write; current hash is {current_hash}"),
        });
    }
    let parent = target
        .parent()
        .ok_or_else(|| bad_request("write target has no parent"))?;
    std::fs::create_dir_all(parent).map_err(internal)?;
    let stage = parent.join(format!(".flycockpit-stage-{operation_id}"));
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&stage)
        .map_err(internal)?;
    file.write_all(content.as_bytes()).map_err(internal)?;
    file.sync_all().map_err(internal)?;
    drop(file);
    std::fs::rename(&stage, &target).map_err(internal)?;
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(internal)?;
    Ok(Response::FsWrite { hash: desired_hash })
}

pub(crate) fn fs_write_sync(
    ctx: &DaemonContext,
    project_root: &str,
    path: &str,
    content: &str,
    base_hash: Option<String>,
) -> Result<Response, ErrorPayload> {
    let root = canonical_project_root(project_root)?;
    let target = resolve_for_write(&root, path)?;
    let locks = ctx.registry.locks();
    let _guard = locks
        .acquire_transient(&target, REMOTE_FILE_AGENT)
        .map_err(lock_conflict)?;

    let current_hash =
        crate::resource_limits::hash_existing_or_empty(&target).map_err(resource_limit)?;
    if let Some(expected) = base_hash.as_deref()
        && expected != current_hash
    {
        return Err(ErrorPayload {
            code: ErrorCode::HashMismatch,
            message: format!("file changed before write; current hash is {current_hash}"),
        });
    }

    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(internal)?;
    }
    std::fs::write(&target, content.as_bytes()).map_err(internal)?;
    let hash = content_hash(content.as_bytes());
    Ok(Response::FsWrite { hash })
}

pub async fn fs_create_dir(project_root: String, path: String) -> Result<Response, ErrorPayload> {
    join_fs_handler(
        "fs_create_dir",
        tokio::task::spawn_blocking(move || fs_create_dir_blocking(&project_root, &path)),
    )
    .await
}

pub async fn fs_create_dir_reconciled_remote(
    project_root: String,
    path: String,
) -> Result<Response, ErrorPayload> {
    join_fs_handler(
        "fs_create_dir",
        tokio::task::spawn_blocking(move || {
            let root = canonical_project_root(&project_root)?;
            let target = resolve_for_write(&root, &path)?;
            if target.try_exists().map_err(internal)? {
                if target.is_dir() {
                    return Ok(Response::Ack);
                }
                return Err(bad_request(format!(
                    "`{path}` exists and is not a directory"
                )));
            }
            std::fs::create_dir_all(&target).map_err(internal)?;
            let parent = target
                .parent()
                .ok_or_else(|| bad_request("directory target has no parent"))?;
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(internal)?;
            Ok(Response::Ack)
        }),
    )
    .await
}

pub(crate) fn fs_create_dir_blocking(
    project_root: &str,
    path: &str,
) -> Result<Response, ErrorPayload> {
    let root = canonical_project_root(project_root)?;
    let target = resolve_for_write(&root, path)?;
    std::fs::create_dir_all(&target).map_err(internal)?;
    Ok(Response::Ack)
}

pub async fn fs_rename(
    ctx: Arc<DaemonContext>,
    project_root: String,
    from_path: String,
    to_path: String,
) -> Result<Response, ErrorPayload> {
    join_fs_handler(
        "fs_rename",
        tokio::task::spawn_blocking(move || {
            fs_rename_blocking(&ctx, &project_root, &from_path, &to_path)
        }),
    )
    .await
}

pub(crate) fn fs_rename_blocking(
    ctx: &DaemonContext,
    project_root: &str,
    from_path: &str,
    to_path: &str,
) -> Result<Response, ErrorPayload> {
    let root = canonical_project_root(project_root)?;
    let from = resolve_existing_path(&root, from_path)?;
    let to = resolve_for_write(&root, to_path)?;
    let locks = ctx.registry.locks();
    let _from_guard = locks
        .acquire_transient(&from, REMOTE_FILE_AGENT)
        .map_err(lock_conflict)?;
    let _to_guard = locks
        .acquire_transient(&to, REMOTE_FILE_AGENT)
        .map_err(lock_conflict)?;
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent).map_err(internal)?;
    }
    std::fs::rename(&from, &to).map_err(internal)?;
    Ok(Response::Ack)
}

pub async fn fs_delete(
    ctx: Arc<DaemonContext>,
    project_root: String,
    path: String,
) -> Result<Response, ErrorPayload> {
    join_fs_handler(
        "fs_delete",
        tokio::task::spawn_blocking(move || fs_delete_blocking(&ctx, &project_root, &path)),
    )
    .await
}

pub(crate) fn fs_delete_blocking(
    ctx: &DaemonContext,
    project_root: &str,
    path: &str,
) -> Result<Response, ErrorPayload> {
    let root = canonical_project_root(project_root)?;
    let target = resolve_existing_path(&root, path)?;
    let locks = ctx.registry.locks();
    let _guard = locks
        .acquire_transient(&target, REMOTE_FILE_AGENT)
        .map_err(lock_conflict)?;
    let meta = std::fs::symlink_metadata(&target).map_err(internal)?;
    if meta.is_dir() {
        std::fs::remove_dir_all(&target).map_err(internal)?;
    } else {
        std::fs::remove_file(&target).map_err(internal)?;
    }
    Ok(Response::Ack)
}

pub async fn git_status(project_root: String) -> Result<Response, ErrorPayload> {
    join_fs_handler(
        "git_status",
        tokio::task::spawn_blocking(move || git_status_blocking(&project_root)),
    )
    .await
}

pub(crate) fn git_status_blocking(project_root: &str) -> Result<Response, ErrorPayload> {
    let root = canonical_project_root(project_root)?;
    let outcome = crate::git::run_git(&root, &["status", "--porcelain=v2"]).map_err(internal)?;
    if !outcome.success {
        return Err(bad_request(outcome.stderr.trim().to_string()));
    }
    let entries = outcome
        .stdout
        .lines()
        .map(|raw| GitStatusEntry {
            raw: raw.to_string(),
        })
        .collect();
    Ok(Response::GitStatus { entries })
}

pub async fn git_diff_file(project_root: String, path: String) -> Result<Response, ErrorPayload> {
    join_fs_handler(
        "git_diff_file",
        tokio::task::spawn_blocking(move || git_diff_file_blocking(&project_root, &path)),
    )
    .await
}

pub(crate) fn git_diff_file_blocking(
    project_root: &str,
    path: &str,
) -> Result<Response, ErrorPayload> {
    let root = canonical_project_root(project_root)?;
    let resolved = resolve_existing_or_parent_path(&root, path)?;
    let rel = resolved
        .strip_prefix(&root)
        .map_err(|_| path_outside_root(path))?
        .to_string_lossy()
        .into_owned();
    let outcome = crate::git::run_git(&root, &["diff", "--", &rel]).map_err(internal)?;
    if !outcome.success {
        return Err(bad_request(outcome.stderr.trim().to_string()));
    }
    let (diff, truncated) = truncate_git_diff_text(outcome.stdout);
    Ok(Response::GitDiffFile { diff, truncated })
}

pub async fn git_diff(
    project_root: String,
    source: GitReadSource,
) -> Result<Response, ErrorPayload> {
    join_fs_handler(
        "git_diff",
        tokio::task::spawn_blocking(move || git_diff_blocking(&project_root, source)),
    )
    .await
}

pub(crate) fn git_diff_blocking(
    project_root: &str,
    source: GitReadSource,
) -> Result<Response, ErrorPayload> {
    let root = canonical_project_root(project_root)?;
    let diff = match &source {
        GitReadSource::Worktree => crate::git::diff_worktree(&root),
        GitReadSource::Staged => crate::git::diff_staged(&root),
        _ => return Err(bad_request("unsupported source for git_diff")),
    }
    .map_err(|error| bad_request(format!("{error:#}")))?;
    let (diff, truncated) = truncate_git_diff_text(diff);
    Ok(Response::GitDiff {
        source,
        diff,
        truncated,
    })
}

/// Cap git-diff payloads at the same text ceiling as `fs_read`, on a char
/// boundary, so a huge worktree diff cannot balloon the daemon response.
fn truncate_git_diff_text(diff: String) -> (String, bool) {
    let limits = crate::resource_limits::ResourceLimits::defaults();
    let cap =
        cockpit_host::text::floor_char_boundary(&diff, limits.fs_read_text_bytes.min(diff.len()));
    let truncated = diff.len() > cap;
    (diff[..cap].to_string(), truncated)
}

pub async fn git_review_sources(
    project_root: String,
    sources: Vec<GitReadSource>,
) -> Result<Response, ErrorPayload> {
    join_fs_handler(
        "git_review_sources",
        tokio::task::spawn_blocking(move || git_review_sources_blocking(&project_root, sources)),
    )
    .await
}

pub(crate) fn git_review_sources_blocking(
    project_root: &str,
    sources: Vec<GitReadSource>,
) -> Result<Response, ErrorPayload> {
    const MAX_REVIEW_SOURCES: usize = 4;

    if sources.is_empty() || sources.len() > MAX_REVIEW_SOURCES {
        return Err(bad_request(
            "git review source count must be between 1 and 4",
        ));
    }
    let root = canonical_project_root(project_root)?;
    let mut results = Vec::with_capacity(sources.len());
    for source in sources {
        let projection = match &source {
            GitReadSource::Worktree => crate::git::review_source_uncommitted(&root),
            GitReadSource::Unstaged => crate::git::review_source_unstaged(&root),
            GitReadSource::Unpushed => crate::git::review_source_unpushed(&root),
            GitReadSource::PullRequest(pr) if valid_pr_reference(pr) => {
                crate::git::review_source_pr(&root, pr)
            }
            GitReadSource::PullRequest(_) => Err(anyhow::anyhow!(
                "PR source requires a non-empty, single-line reference of at most 256 bytes"
            )),
            GitReadSource::Staged => Err(anyhow::anyhow!(
                "staged is a diff-pane source, not a multireview source"
            )),
        };
        results.push(match projection {
            Ok(projection) => GitReviewSourceResult {
                source,
                label: projection.label,
                command: Some(projection.command),
                has_changes: !projection.diff.trim().is_empty(),
                error: None,
            },
            Err(error) => GitReviewSourceResult {
                label: review_source_label(&source),
                source,
                command: None,
                has_changes: false,
                error: Some(format!("{error:#}")),
            },
        });
    }
    Ok(Response::GitReviewSources { sources: results })
}

fn review_source_label(source: &GitReadSource) -> String {
    match source {
        GitReadSource::Worktree => "Uncommitted changes".into(),
        GitReadSource::Staged => "Staged changes".into(),
        GitReadSource::Unstaged => "Unstaged changes".into(),
        GitReadSource::Unpushed => "Unpushed changes".into(),
        GitReadSource::PullRequest(pr) if valid_pr_reference(pr) => {
            format!("PR {}", pr.trim())
        }
        GitReadSource::PullRequest(_) => "PR".into(),
    }
}

fn valid_pr_reference(pr: &str) -> bool {
    !pr.trim().is_empty()
        && pr.len() <= GIT_REVIEW_PR_REFERENCE_BYTE_CAP
        && pr.chars().all(|ch| !ch.is_control() && ch != '`')
}

pub async fn git_repo_status(project_root: String) -> Result<Response, ErrorPayload> {
    join_fs_handler(
        "git_repo_status",
        tokio::task::spawn_blocking(move || git_repo_status_blocking(&project_root)),
    )
    .await
}

pub(crate) fn git_repo_status_blocking(project_root: &str) -> Result<Response, ErrorPayload> {
    let root = canonical_project_root(project_root)?;
    let status = crate::git::repo_status(&root).map_err(internal)?;
    Ok(Response::GitRepoStatus { status })
}

pub async fn find_worktree_root(path: String) -> Result<Response, ErrorPayload> {
    join_fs_handler(
        "find_worktree_root",
        tokio::task::spawn_blocking(move || find_worktree_root_blocking(&path)),
    )
    .await
}

pub(crate) fn find_worktree_root_blocking(path: &str) -> Result<Response, ErrorPayload> {
    let root = crate::git::find_worktree_root(std::path::Path::new(path))
        .map(|root| root.display().to_string());
    Ok(Response::WorktreeRoot { root })
}

async fn join_fs_handler(
    request_kind: &'static str,
    handle: tokio::task::JoinHandle<Result<Response, ErrorPayload>>,
) -> Result<Response, ErrorPayload> {
    match handle.await {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(request_kind, %error, "filesystem handler panicked");
            Err(ErrorPayload {
                code: ErrorCode::Internal,
                message: "filesystem handler panicked".to_string(),
            })
        }
    }
}

fn entry_to_wire(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    root: &Path,
    path: PathBuf,
    name: String,
) -> Result<FsEntry, ErrorPayload> {
    let meta = std::fs::symlink_metadata(&path).map_err(internal)?;
    let is_symlink = meta.file_type().is_symlink();
    let canonical = std::fs::canonicalize(&path).ok();
    let escapes_root = canonical.as_deref().is_none_or(|p| !p.starts_with(root));
    let gitignored = canonical
        .as_deref()
        .map(crate::gitignore::is_gitignored)
        .unwrap_or(false);
    let secret_blocked = canonical
        .as_deref()
        .map(|p| secret_blocked_for_sharee(ctx, principal, root, p))
        .transpose()?
        .unwrap_or(false);
    let kind = if is_symlink {
        FsEntryKind::Symlink
    } else if meta.is_dir() {
        FsEntryKind::Directory
    } else if meta.is_file() {
        FsEntryKind::File
    } else {
        FsEntryKind::Other
    };
    let rel = path
        .strip_prefix(root)
        .unwrap_or(&path)
        .to_string_lossy()
        .into_owned();
    let symlink_target = if is_symlink {
        std::fs::read_link(&path)
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    } else {
        None
    };
    Ok(FsEntry {
        name,
        path: rel,
        kind,
        size: meta.len(),
        mtime_ms: meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_millis().min(i64::MAX as u128) as i64),
        gitignored,
        blocked: escapes_root || secret_blocked,
        symlink_target,
    })
}

fn read_kind_for_path(path: &Path, binary: bool) -> FsReadKind {
    if is_image_path(path) {
        FsReadKind::Image
    } else if binary {
        FsReadKind::Binary
    } else {
        FsReadKind::Text
    }
}

fn is_image_path(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .map(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp"
            )
        })
        .unwrap_or(false)
}

fn ensure_read_allowed(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    root: &Path,
    path: &Path,
) -> Result<(), ErrorPayload> {
    if secret_blocked_for_sharee(ctx, principal, root, path)? {
        return Err(ErrorPayload {
            code: ErrorCode::Authorization,
            message: "remote principal cannot read gitignored or dotenv-protected files".into(),
        });
    }
    Ok(())
}

fn secret_blocked_for_sharee(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    root: &Path,
    path: &Path,
) -> Result<bool, ErrorPayload> {
    if principal.is_owner() {
        return Ok(false);
    }
    Ok(crate::gitignore::is_gitignored(path) || dotenv_pattern_matches(ctx, root, path)?)
}

fn dotenv_pattern_matches(
    ctx: &DaemonContext,
    root: &Path,
    path: &Path,
) -> Result<bool, ErrorPayload> {
    let trust_root = crate::config::trust::resolve_trust_root(root).map_err(internal)?;
    let root_for_db = trust_root.root.clone();
    let trust_policy = ctx
        .db
        .blocking_write_for_sync_maintenance(move |conn| {
            let decision = crate::db::Db::workspace_trust_by_root_conn(conn, &root_for_db)?;
            let Some(decision) = decision else {
                anyhow::bail!("workspace trust is unset for {}", root_for_db.display());
            };
            if decision.mode == crate::db::workspace_trust::WorkspaceTrustMode::Untrusted {
                anyhow::bail!("workspace {} is untrusted", root_for_db.display());
            }
            Ok(crate::config::trust::WorkspaceTrustPolicy {
                root: trust_root,
                mode: decision.mode,
            })
        })
        .map_err(internal)?;
    let cfg = ctx
        .config_source()
        .load_with_trust(root, &trust_policy)
        .map_err(internal)?
        .1
        .redact;
    if cfg
        .extra_dotenv_paths
        .iter()
        .any(|extra| std::fs::canonicalize(extra).ok().as_deref() == Some(path))
    {
        return Ok(true);
    }
    let matcher = crate::gitignore::build_allowlist_matcher(root, &cfg.dotenv_patterns);
    Ok(matches!(
        matcher.matched_path_or_any_parents(path, path.is_dir()),
        Match::Ignore(_)
    ))
}

pub(crate) fn canonical_project_root(project_root: &str) -> Result<PathBuf, ErrorPayload> {
    let root = Path::new(project_root);
    match std::fs::canonicalize(root) {
        Ok(path) if path.is_dir() => Ok(path),
        Ok(_) => Err(ErrorPayload {
            code: ErrorCode::RootMissing,
            message: format!("project root `{project_root}` is not a directory"),
        }),
        Err(e) => Err(ErrorPayload {
            code: ErrorCode::RootMissing,
            message: format!("project root `{project_root}` is unavailable: {e}"),
        }),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorizedCanonicalPathMode {
    Existing,
    WriteTarget,
    RenameSource,
}

/// Resolve an already-authorized request path through the same symlink-aware
/// containment rules used by production filesystem handlers.
pub(crate) fn resolve_authorized_canonical_path(
    project_root: &str,
    path: &str,
    mode: AuthorizedCanonicalPathMode,
) -> Result<PathBuf, ErrorPayload> {
    let root = canonical_project_root(project_root)?;
    match mode {
        AuthorizedCanonicalPathMode::Existing => resolve_existing_path(&root, path),
        AuthorizedCanonicalPathMode::WriteTarget => resolve_existing_or_parent_path(&root, path),
        AuthorizedCanonicalPathMode::RenameSource => resolve_rename_source(&root, path),
    }
}

fn resolve_rename_source(root: &Path, path: &str) -> Result<PathBuf, ErrorPayload> {
    let rel = clean_relative_path(path)?;
    let name = rel
        .file_name()
        .ok_or_else(|| bad_request("rename source must name an entry"))?;
    let parent_rel = rel.parent().unwrap_or_else(|| Path::new(""));
    let parent = resolve_existing_path(root, parent_rel.to_str().unwrap_or(""))?;
    if !parent.is_dir() {
        return Err(bad_request("rename source parent is not a directory"));
    }
    Ok(parent.join(name))
}

fn resolve_existing_path(root: &Path, path: &str) -> Result<PathBuf, ErrorPayload> {
    let rel = clean_relative_path(path)?;
    let joined = root.join(rel);
    let canonical = std::fs::canonicalize(&joined)
        .map_err(|e| bad_request(format!("cannot access `{path}`: {e}")))?;
    if canonical.starts_with(root) {
        Ok(canonical)
    } else {
        Err(path_outside_root(path))
    }
}

fn resolve_existing_or_parent_path(root: &Path, path: &str) -> Result<PathBuf, ErrorPayload> {
    match resolve_existing_path(root, path) {
        Ok(path) => Ok(path),
        Err(_) => resolve_for_write(root, path),
    }
}

fn resolve_for_write(root: &Path, path: &str) -> Result<PathBuf, ErrorPayload> {
    let rel = clean_relative_path(path)?;
    if rel.as_os_str().is_empty() {
        return Err(bad_request("path must name a file or directory"));
    }
    let joined = root.join(&rel);
    match std::fs::symlink_metadata(&joined) {
        Ok(_) => return resolve_existing_path(root, path),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(bad_request(format!("cannot access `{path}`: {err}"))),
    }
    let mut ancestor = joined
        .parent()
        .ok_or_else(|| bad_request("path has no parent directory"))?;
    while !ancestor.try_exists().map_err(internal)? {
        ancestor = ancestor
            .parent()
            .ok_or_else(|| bad_request(format!("parent for `{path}` is unavailable")))?;
    }
    let canonical_ancestor = std::fs::canonicalize(ancestor)
        .map_err(|e| bad_request(format!("parent for `{path}` is unavailable: {e}")))?;
    if !canonical_ancestor.starts_with(root) {
        return Err(path_outside_root(path));
    }
    let unresolved = joined
        .strip_prefix(ancestor)
        .map_err(|_| bad_request(format!("parent for `{path}` is unavailable")))?;
    Ok(canonical_ancestor.join(unresolved))
}

fn clean_relative_path(path: &str) -> Result<PathBuf, ErrorPayload> {
    let input = Path::new(path);
    if input.is_absolute() {
        return Err(path_outside_root(path));
    }
    let mut out = PathBuf::new();
    for component in input.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => out.push(part),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(path_outside_root(path));
            }
        }
    }
    Ok(out)
}

fn content_hash(bytes: &[u8]) -> String {
    crate::resource_limits::sha256_hex(bytes)
}

fn path_outside_root(path: &str) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::PathOutsideRoot,
        message: format!("`{path}` resolves outside the project root"),
    }
}

fn lock_conflict(err: anyhow::Error) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::LockConflict,
        message: format!("{err:#}"),
    }
}

fn bad_request(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::BadRequest,
        message: message.into(),
    }
}

fn resource_limit(error: crate::resource_limits::ResourceLimitError) -> ErrorPayload {
    match error {
        crate::resource_limits::ResourceLimitError::ByteLimit { .. } => {
            bad_request(error.to_string())
        }
        other => internal(other),
    }
}

fn conflict(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::Conflict,
        message: message.into(),
    }
}

/// Fail-closed mapping for a `SaveExtendedConfig` merge failure. The underlying
/// serde/anyhow error is DELIBERATELY discarded: a config.json parse error can
/// echo attacker/legacy-supplied bytes (`invalid type: string "…"`) and
/// config.json can carry literal secrets in pre-redaction legacy layers, so the
/// error detail must never reach the client. Names only the boundary.
fn bad_request_config<E>(_error: E) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::BadRequest,
        message: "configuration payload is not valid config.json".into(),
    }
}

/// Stable, non-secret policy feedback for settings clients. Unlike a generic
/// serde failure, this is an intentional user-facing rejection of a valid JSON
/// shape whose requested trust relationship cannot be honored.
fn invalid_knowledge_base_trust_config() -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::BadRequest,
        message: "knowledge-base trust configuration is invalid: trustRequired is local-only and dreamModel must be trusted"
            .into(),
    }
}

fn internal<E: std::fmt::Display>(err: E) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::Internal,
        message: format!("{err:#}"),
    }
}

#[cfg(test)]
mod tests {
    #![allow(deprecated)]

    use super::*;
    use crate::daemon::principal::ClientPrincipal;
    #[cfg(feature = "remote")]
    use crate::daemon::principal::{PrincipalGrant, PrincipalScope};

    fn test_ctx(root: &Path) -> crate::daemon::server::DaemonContext {
        let db = crate::db::Db::open_in_memory().expect("in-memory db");
        let normalized_root = root.canonicalize().unwrap().to_string_lossy().into_owned();
        db.blocking_write_for_sync_maintenance(move |conn| {
            crate::db::Db::set_workspace_trust_conn(
                conn,
                &normalized_root,
                crate::db::workspace_trust::WorkspaceTrustMode::Trust,
                1,
            )
            .map(|_| ())
        })
        .expect("trust root");
        let locks = std::sync::Arc::new(crate::locks::LockManager::in_memory(db.clone()));
        crate::daemon::server::DaemonContext::new(
            db,
            locks,
            crate::daemon::DaemonPaths {
                socket: PathBuf::from("/tmp/cockpit-fs-test.sock"),
                pid_file: PathBuf::from("/tmp/cockpit-fs-test.pid"),
                ephemeral: true,
            },
            crate::daemon::terminal::test_host_factory(),
            crate::daemon::config_source::ConfigSource::fixed(
                crate::config::providers::ProvidersConfig::default(),
                crate::config::extended::ExtendedConfig::default(),
            ),
        )
    }

    #[cfg(feature = "remote")]
    fn remote_project_files(root: &Path) -> ClientPrincipal {
        ClientPrincipal::from_verified_remote(
            "user-1".into(),
            vec![PrincipalGrant {
                scope: PrincipalScope::ProjectFiles,
                project_root: Some(root.to_string_lossy().into_owned()),
            }],
            None,
        )
    }

    #[test]
    fn rejects_traversal_absolute_and_prefix_collision() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("app");
        let sibling = tmp.path().join("app2");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&sibling).unwrap();
        std::fs::write(root.join("ok.txt"), "ok").unwrap();
        std::fs::write(sibling.join("secret.txt"), "no").unwrap();

        assert!(
            resolve_existing_path(&root.canonicalize().unwrap(), "../app2/secret.txt").is_err()
        );
        assert!(
            resolve_existing_path(
                &root.canonicalize().unwrap(),
                sibling.join("secret.txt").to_str().unwrap()
            )
            .is_err()
        );
        assert!(resolve_existing_path(&root.canonicalize().unwrap(), "ok.txt").is_ok());
    }

    #[test]
    fn authorized_resolver_distinguishes_existing_and_write_targets() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("app");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("present.txt"), "ok").unwrap();
        let root_text = root.to_str().unwrap();
        let existing = resolve_authorized_canonical_path(
            root_text,
            "./present.txt",
            AuthorizedCanonicalPathMode::Existing,
        )
        .unwrap();
        assert_eq!(existing, root.canonicalize().unwrap().join("present.txt"));
        assert!(
            resolve_authorized_canonical_path(
                root_text,
                "missing.txt",
                AuthorizedCanonicalPathMode::Existing,
            )
            .is_err()
        );
        assert_eq!(
            resolve_authorized_canonical_path(
                root_text,
                "missing.txt",
                AuthorizedCanonicalPathMode::WriteTarget,
            )
            .unwrap(),
            root.canonicalize().unwrap().join("missing.txt")
        );
    }

    #[test]
    fn rename_source_identity_is_stable_after_entry_disappears() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("app");
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("nested/from.txt"), b"value").unwrap();
        let root_text = root.to_str().unwrap();
        let before = resolve_authorized_canonical_path(
            root_text,
            "nested/from.txt",
            AuthorizedCanonicalPathMode::RenameSource,
        )
        .unwrap();
        std::fs::rename(root.join("nested/from.txt"), root.join("nested/to.txt")).unwrap();
        let after = resolve_authorized_canonical_path(
            root_text,
            "nested/from.txt",
            AuthorizedCanonicalPathMode::RenameSource,
        )
        .unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn staged_write_reconciles_rename_before_ledger_commit_without_rewriting() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("app");
        std::fs::create_dir_all(&root).unwrap();
        let ctx = test_ctx(&root);
        let root_text = root.to_str().unwrap();
        let operation = "01890f3e-4c00-7000-8000-00000000009f";
        let first = fs_write_staged_sync(
            &ctx,
            root_text,
            "nested/value.txt",
            "durable value",
            None,
            operation,
        )
        .unwrap();
        let modified = std::fs::metadata(root.join("nested/value.txt"))
            .unwrap()
            .modified()
            .unwrap();
        let reconciled = fs_write_staged_sync(
            &ctx,
            root_text,
            "nested/value.txt",
            "durable value",
            Some(content_hash(b"different base")),
            operation,
        )
        .unwrap();
        assert!(matches!(first, Response::FsWrite { .. }));
        assert!(matches!(reconciled, Response::FsWrite { .. }));
        assert_eq!(
            std::fs::metadata(root.join("nested/value.txt"))
                .unwrap()
                .modified()
                .unwrap(),
            modified,
            "reconciliation observes the desired target and does not rewrite"
        );
        assert!(
            !root
                .join("nested")
                .join(format!(".flycockpit-stage-{operation}"))
                .exists()
        );
    }

    #[tokio::test]
    async fn remote_directory_creation_reconciles_only_a_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("app");
        std::fs::create_dir_all(&root).unwrap();
        let root_text = root.to_string_lossy().into_owned();
        assert!(matches!(
            fs_create_dir_reconciled_remote(root_text.clone(), "nested/dir".into())
                .await
                .unwrap(),
            Response::Ack
        ));
        assert!(matches!(
            fs_create_dir_reconciled_remote(root_text.clone(), "nested/dir".into())
                .await
                .unwrap(),
            Response::Ack
        ));
        std::fs::write(root.join("not-a-dir"), b"file").unwrap();
        assert!(
            fs_create_dir_reconciled_remote(root_text, "not-a-dir".into())
                .await
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escape() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("app");
        let outside = tmp.path().join("outside.txt");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&outside, "secret").unwrap();
        symlink(&outside, root.join("link.txt")).unwrap();

        let err = resolve_existing_path(&root.canonicalize().unwrap(), "link.txt").unwrap_err();
        assert_eq!(err.code, ErrorCode::PathOutsideRoot);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_dangling_symlink_for_write() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("app");
        let outside = tmp.path().join("missing.txt");
        std::fs::create_dir_all(&root).unwrap();
        symlink(&outside, root.join("link.txt")).unwrap();

        let err = resolve_for_write(&root.canonicalize().unwrap(), "link.txt").unwrap_err();
        assert_eq!(err.code, ErrorCode::BadRequest);
    }

    #[cfg(unix)]
    #[test]
    fn write_target_canonicalizes_symlink_alias_and_observes_retarget() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("app");
        let first = root.join("first");
        let second = root.join("second");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        symlink("first", root.join("alias")).unwrap();
        let canonical_root = root.canonicalize().unwrap();
        assert_eq!(
            resolve_for_write(&canonical_root, "alias/new.txt").unwrap(),
            resolve_for_write(&canonical_root, "first/new.txt").unwrap()
        );
        std::fs::remove_file(root.join("alias")).unwrap();
        symlink("second", root.join("alias")).unwrap();
        assert_eq!(
            resolve_for_write(&canonical_root, "alias/new.txt").unwrap(),
            canonical_root.join("second/new.txt")
        );
    }

    #[test]
    fn dotenv_file_is_blocked_for_sharee_but_not_owner() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let ctx = test_ctx(root);
        std::fs::write(root.join(".env"), "SECRET=value").unwrap();
        let path = root.join(".env").canonicalize().unwrap();
        #[cfg(feature = "remote")]
        assert!(secret_blocked_for_sharee(&ctx, &remote_project_files(root), root, &path).unwrap());
        assert!(!secret_blocked_for_sharee(&ctx, &ClientPrincipal::owner(), root, &path).unwrap());
    }

    #[cfg(feature = "remote")]
    #[test]
    fn gitignored_file_is_flagged_in_listing() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let ctx = test_ctx(root);
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(".gitignore"), "ignored.txt\n").unwrap();
        std::fs::write(root.join("ignored.txt"), "secret").unwrap();
        let Response::FsList { entries, .. } = fs_list_blocking(
            &ctx,
            &remote_project_files(root),
            root.to_str().unwrap(),
            ".",
            true,
        )
        .unwrap() else {
            panic!("expected fs list");
        };
        let ignored = entries
            .iter()
            .find(|entry| entry.name == "ignored.txt")
            .unwrap();
        assert!(ignored.gitignored);
        assert!(ignored.blocked);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn blocking_fs_read_does_not_occupy_a_runtime_worker() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let file = root.join("read.txt");
        std::fs::write(&file, "read").unwrap();
        let ctx = Arc::new(test_ctx(root));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let release = Arc::new((StdMutex::new(false), std::sync::Condvar::new()));
        set_fs_read_block_for_test(file.canonicalize().unwrap(), entered_tx, release.clone());

        let read_task = tokio::spawn(fs_read(
            ctx,
            ClientPrincipal::owner(),
            root.to_string_lossy().into_owned(),
            "read.txt".to_string(),
            false,
        ));
        entered_rx.await.expect("fs_read entered blocking body");
        let progressed = tokio::spawn(async { 1usize });
        assert_eq!(progressed.await.unwrap(), 1);

        let (lock, cvar) = &*release;
        *lock.lock().unwrap() = true;
        cvar.notify_all();
        let response = read_task.await.unwrap().unwrap();
        assert!(matches!(response, Response::FsRead { .. }));
    }

    #[tokio::test]
    async fn blocking_fs_handler_panic_maps_to_internal_error() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let file = root.join("panic.txt");
        std::fs::write(&file, "panic").unwrap();
        set_fs_read_panic_for_test(file.canonicalize().unwrap());

        let err = fs_read(
            Arc::new(test_ctx(root)),
            ClientPrincipal::owner(),
            root.to_string_lossy().into_owned(),
            "panic.txt".to_string(),
            false,
        )
        .await
        .expect_err("panic maps to internal error");

        assert_eq!(err.code, ErrorCode::Internal);
        assert_eq!(err.message, "filesystem handler panicked");
    }

    #[tokio::test]
    async fn blocking_fs_read_matches_sync_result() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("read.txt"), "read").unwrap();
        let ctx = Arc::new(test_ctx(root));
        let principal = ClientPrincipal::owner();
        let project_root = root.to_string_lossy().into_owned();

        let sync = fs_read_sync(&ctx, &principal, &project_root, "read.txt", false)
            .expect("sync read succeeds");
        let async_result = fs_read(ctx, principal, project_root, "read.txt".to_string(), false)
            .await
            .expect("async read succeeds");

        assert_eq!(
            serde_json::to_value(sync).unwrap(),
            serde_json::to_value(async_result).unwrap()
        );
    }

    #[test]
    fn fs_read_rejects_a_file_over_the_hard_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let file = root.join("huge.bin");
        let handle = std::fs::File::create(&file).unwrap();
        handle
            .set_len(crate::resource_limits::ResourceLimits::defaults().fs_read_max_file_bytes + 1)
            .unwrap();
        drop(handle);
        let ctx = test_ctx(root);
        let err = fs_read_sync(
            &ctx,
            &ClientPrincipal::owner(),
            root.to_str().unwrap(),
            "huge.bin",
            false,
        )
        .expect_err("oversized file must fail closed");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("filesystem read"), "{}", err.message);
    }

    #[test]
    fn fs_write_refuses_an_oversized_existing_target() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let file = root.join("huge.txt");
        let handle = std::fs::File::create(&file).unwrap();
        handle
            .set_len(crate::resource_limits::ResourceLimits::defaults().fs_mutation_read_bytes + 1)
            .unwrap();
        drop(handle);
        let ctx = test_ctx(root);
        let err = fs_write_sync(&ctx, root.to_str().unwrap(), "huge.txt", "new", None)
            .expect_err("oversized prior content must fail closed");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("existing file"), "{}", err.message);
        assert_eq!(
            std::fs::metadata(&file).unwrap().len(),
            crate::resource_limits::ResourceLimits::defaults().fs_mutation_read_bytes + 1
        );
    }

    #[test]
    fn fs_write_staged_refuses_an_oversized_existing_target() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let file = root.join("huge.txt");
        let handle = std::fs::File::create(&file).unwrap();
        handle
            .set_len(crate::resource_limits::ResourceLimits::defaults().fs_mutation_read_bytes + 1)
            .unwrap();
        drop(handle);
        let ctx = test_ctx(root);
        let err = fs_write_staged_sync(
            &ctx,
            root.to_str().unwrap(),
            "huge.txt",
            "new",
            None,
            "op-1",
        )
        .expect_err("oversized prior content must fail closed");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("existing file"), "{}", err.message);
    }

    #[test]
    fn save_extended_config_refuses_an_oversized_existing_target() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let file = root.join("config.json");
        let handle = std::fs::File::create(&file).unwrap();
        handle
            .set_len(crate::resource_limits::ResourceLimits::defaults().fs_mutation_read_bytes + 1)
            .unwrap();
        drop(handle);
        let err = save_extended_config_sync(root.to_str().unwrap(), "config.json", "{}", None)
            .expect_err("oversized config.json must fail closed rather than merge from empty");
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("existing file"), "{}", err.message);
        assert_eq!(
            std::fs::metadata(&file).unwrap().len(),
            crate::resource_limits::ResourceLimits::defaults().fs_mutation_read_bytes + 1
        );
    }

    #[test]
    fn fs_read_truncates_text_without_loading_the_whole_file() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let limits = crate::resource_limits::ResourceLimits::defaults();
        let body = "x".repeat(limits.fs_read_text_bytes + 64);
        std::fs::write(root.join("long.txt"), &body).unwrap();
        let ctx = test_ctx(root);
        let Response::FsRead {
            content,
            truncated,
            hash,
            kind,
        } = fs_read_sync(
            &ctx,
            &ClientPrincipal::owner(),
            root.to_str().unwrap(),
            "long.txt",
            false,
        )
        .expect("in-cap file streams")
        else {
            panic!("expected fs_read");
        };
        assert!(truncated);
        assert_eq!(kind, FsReadKind::Text);
        let content = content.expect("text content");
        assert!(content.len() <= limits.fs_read_text_bytes);
        assert_eq!(hash, crate::resource_limits::sha256_hex(body.as_bytes()));
    }

    /// A valid, non-empty registry: one hosted OpenAI-images endpoint plus an
    /// enabled default target referencing it. Built through the single
    /// `ImageGenerationConfig::new` validation funnel.
    fn sample_image_registry() -> cockpit_config::config::image_generation::ImageGenerationConfig {
        use cockpit_config::config::image_generation::{
            IMAGE_GENERATION_ROUTE_PROFILE_VERSION, ImageAdapterKind, ImageCapabilityEvidence,
            ImageDimensionDescriptor, ImageDimensionRequestPolicy, ImageEndpoint, ImageFormat,
            ImageGenerationConfig, ImageGenerationTarget, ImageLocationClass, ImagePrice,
            ImageTargetIdentity, ReferenceImageSupport,
        };
        use cockpit_config::config::providers::CapabilityStatus;

        let endpoint = ImageEndpoint {
            id: "openai-main".into(),
            adapter: ImageAdapterKind::OpenaiImages,
            origin: "https://api.openai.com/".into(),
            path_prefix: None,
            credential_ref: Some("openai-key".into()),
            headers: Vec::new(),
            allow_insecure_transport: false,
            location: ImageLocationClass::PublicCloud,
            enabled: true,
            route_profile_version: IMAGE_GENERATION_ROUTE_PROFILE_VERSION,
            exclusive_server: false,
        };
        let target = ImageGenerationTarget {
            id: "gpt-image".into(),
            display_name: None,
            endpoint_id: "openai-main".into(),
            identity: ImageTargetIdentity::HostedModel {
                model: "gpt-image-1".into(),
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
            parameters: Vec::new(),
            openrouter_routing: None,
            generation_capability: ImageCapabilityEvidence::new(CapabilityStatus::Unknown, None)
                .unwrap(),
            price: ImagePrice::Unknown,
        };
        ImageGenerationConfig::new(vec![endpoint], vec![target], Vec::new(), Vec::new())
            .expect("valid sample registry")
    }

    /// Regression: a generic `SaveExtendedConfig` whose incoming
    /// `image_generation` is the redacted EMPTY default (exactly what a client
    /// round-trips from the snapshot, where the daemon replaced the registry via
    /// `redacted_for_snapshot`) must NOT wipe the non-empty on-disk registry.
    /// Before the fix this wrote the incoming doc verbatim and destroyed the
    /// endpoints/targets/workflows/allowlist.
    #[test]
    fn save_extended_config_preserves_on_disk_image_generation_registry() {
        use cockpit_config::config::image_generation::ImageGenerationConfig;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let root_text = root.to_str().unwrap();

        // Seed a non-empty registry on disk (NOT via SaveExtendedConfig, which
        // strips it — that is the whole point).
        let registry = sample_image_registry();
        let on_disk_value = serde_json::json!({
            "redact": { "enabled": true, "denylist": ["SEED-KEEP"] },
            "image_generation": serde_json::to_value(&registry).unwrap(),
        });
        let on_disk_str = format!(
            "{}\n",
            serde_json::to_string_pretty(&on_disk_value).unwrap()
        );
        std::fs::write(root.join("config.json"), &on_disk_str).unwrap();

        // Precondition / non-vacuity: the registry really is on disk.
        assert!(
            on_disk_str.contains("openai-main"),
            "seed must persist the endpoint"
        );
        let seeded: ImageGenerationConfig =
            serde_json::from_value(on_disk_value.get("image_generation").unwrap().clone()).unwrap();
        assert_eq!(seeded.endpoints().len(), 1);

        // Incoming = faithful redacted round-trip: same doc, but with an EMPTY
        // image_generation (the redacted value) and one OTHER field changed.
        let mut incoming = on_disk_value.clone();
        incoming["image_generation"] =
            serde_json::to_value(ImageGenerationConfig::default()).unwrap();
        incoming["name"] = serde_json::json!("Renamed Project");
        let incoming_str = serde_json::to_string(&incoming).unwrap();
        // Precondition: a VERBATIM write of this payload would wipe the registry.
        assert!(
            !incoming_str.contains("openai-main"),
            "the redacted incoming payload must not carry the registry"
        );

        let resp =
            save_extended_config_sync(root_text, "config.json", &incoming_str, None).unwrap();
        assert!(matches!(resp, Response::ExtendedConfigWritten { .. }));

        // The registry is preserved AND the other change landed.
        let after = std::fs::read_to_string(root.join("config.json")).unwrap();
        assert!(
            after.contains("Renamed Project"),
            "other config sections must still be saved verbatim"
        );
        let after_value: serde_json::Value = serde_json::from_str(&after).unwrap();
        let preserved: ImageGenerationConfig = serde_json::from_value(
            after_value
                .get("image_generation")
                .expect("image_generation must be preserved on disk")
                .clone(),
        )
        .expect("preserved image_generation is a valid registry");
        assert_eq!(
            preserved.endpoints().len(),
            1,
            "the on-disk endpoint registry must survive a generic settings save"
        );
        assert_eq!(preserved.endpoints()[0].id, "openai-main");
        assert_eq!(preserved.targets().len(), 1);
    }

    /// A `SaveExtendedConfig` that actually changes config.json advances the
    /// daemon config generation (so the image-control-plane generation CAS
    /// observes the write); a no-op save writes nothing and does NOT bump.
    #[test]
    fn save_extended_config_bumps_generation_only_on_a_real_write() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let root_text = root.to_str().unwrap();
        std::fs::write(root.join("config.json"), "{}\n").unwrap();

        let content = serde_json::json!({ "name": "Alpha" }).to_string();
        let before = crate::daemon::server::inventory::current_config_generation();
        save_extended_config_sync(root_text, "config.json", &content, None).unwrap();
        let after_write = crate::daemon::server::inventory::current_config_generation();
        assert_eq!(
            after_write,
            before + 1,
            "a config.json write must advance the config generation"
        );

        // Identical content renders to identical merged bytes -> no write.
        save_extended_config_sync(root_text, "config.json", &content, None).unwrap();
        let after_noop = crate::daemon::server::inventory::current_config_generation();
        assert_eq!(
            after_noop, after_write,
            "an unchanged save must not bump the generation (no bump-without-write)"
        );
    }

    #[test]
    fn denylist_occurrence_ids_disambiguate_equal_masks_and_preserve_order() {
        let mut document = serde_json::json!({
            "redact": { "denylist": ["same", "same"] }
        });
        let object = document.as_object_mut().unwrap();
        let result = apply_denylist_sequence(
            object,
            vec![
                cockpit_proto::DesiredDenylistEntry::Existing {
                    entry_id: "second".into(),
                },
                cockpit_proto::DesiredDenylistEntry::New {
                    // Nonces must be canonical UUIDs; anything else is refused.
                    client_nonce: "6a1f0f6e-9f7b-4a0e-8c8e-2b54a1f0c9d3".into(),
                    literal: cockpit_proto::SensitiveWireLiteral::new("new-value".into()),
                },
            ],
            &["first".into(), "second".into()],
        )
        .unwrap();
        assert_eq!(result[0], ("second".into(), None, "same".into()));
        assert_eq!(
            result[1].1.as_deref(),
            Some("6a1f0f6e-9f7b-4a0e-8c8e-2b54a1f0c9d3")
        );
        assert_ne!(result[1].0, "first");
        assert_eq!(
            document["redact"]["denylist"],
            serde_json::json!(["same", "new-value"])
        );
    }

    #[test]
    fn denylist_rejects_typed_display_mask_literal() {
        for (index, literal) in ["••••", "•••• (4 bytes)", "********", "******** #1"]
            .into_iter()
            .enumerate()
        {
            let mut document = serde_json::json!({"redact": {"denylist": []}});
            let error = apply_denylist_sequence(
                document.as_object_mut().unwrap(),
                vec![cockpit_proto::DesiredDenylistEntry::New {
                    client_nonce: format!("00000000-0000-4000-8000-{index:012}"),
                    literal: cockpit_proto::SensitiveWireLiteral::new(literal.into()),
                }],
                &[],
            )
            .unwrap_err();
            assert_eq!(error.code, ErrorCode::BadRequest, "literal: {literal}");
        }
    }

    #[test]
    fn typed_patch_recovery_stays_a_write_ahead_startup_boundary() {
        let source = include_str!("fs_api.rs");
        let apply = source
            .split("pub async fn apply_extended_config_patch")
            .nth(1)
            .and_then(|tail| tail.split("async fn settings_snapshot_root").next())
            .expect("typed patch implementation");
        let release = apply.find("drop(_guard)").expect("config lock release");
        let prepare = apply
            .find("INSERT INTO extended_config_patch_journals")
            .expect("durable prepare");
        let publication = apply
            .find("write_config_bytes_atomic")
            .expect("atomic publication");
        assert!(release < prepare && prepare < publication);
        assert!(apply.contains("drop(_publication_guard)"));
        let refresh = apply
            .find("ctx.refresh_redaction_table()")
            .expect("redaction publication reconciliation");
        let settlement = apply
            .rfind("UPDATE local_operation_receipts SET state='terminal_success'")
            .expect("atomic terminal settlement");
        assert!(publication < refresh && refresh < settlement);

        let startup = include_str!("server/mod.rs");
        let recovery = startup
            .find("recover_extended_config_patch_journals")
            .expect("typed patch startup recovery");
        let generic = startup
            .find("settle_interrupted_local_operations")
            .expect("generic interrupted settlement");
        assert!(recovery < generic);
    }
}
