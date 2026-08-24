use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
#[cfg(test)]
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant, UNIX_EPOCH};

use base64::Engine as _;
use ignore::Match;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::daemon::principal::ClientPrincipal;
use crate::daemon::proto::{
    ErrorCode, ErrorPayload, FsEntry, FsEntryKind, FsReadKind, GitStatusEntry, Response,
};
use crate::daemon::server::DaemonContext;

const FS_LIST_ENTRY_CAP: usize = 1_000;
const FS_TEXT_READ_BYTE_CAP: usize = crate::tools::common::OUTPUT_BYTE_CAP;
const FS_BINARY_READ_BYTE_CAP: usize = 256 * 1024;
const REMOTE_FILE_AGENT: &str = "remote-project-files";
const SETTINGS_CAPABILITY_TTL: Duration = Duration::from_secs(30 * 60);
const SETTINGS_CAPABILITY_GLOBAL_CAP: usize = 256;
const SETTINGS_CAPABILITY_OWNER_CAP: usize = 32;

#[derive(Clone)]
struct SettingsCapability {
    owner: String,
    root: PathBuf,
    target: PathBuf,
    revision: String,
    identity: Option<cockpit_config::config::TerminalIngressFileIdentity>,
    denylist_ids: Vec<String>,
    issued_at: Instant,
    expires_at: Instant,
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

    let bytes = std::fs::read(&resolved).map_err(internal)?;
    let hash = content_hash(&bytes);
    let binary = crate::tools::common::looks_binary(&bytes);
    let kind = read_kind_for_path(&resolved, binary);
    if binary || wants_base64 {
        if !wants_base64 && !matches!(kind, FsReadKind::Image) {
            return Ok(Response::FsRead {
                content: None,
                hash,
                truncated: bytes.len() > FS_BINARY_READ_BYTE_CAP,
                kind,
            });
        }
        let cap = FS_BINARY_READ_BYTE_CAP.min(bytes.len());
        let truncated = bytes.len() > cap;
        let content = base64::engine::general_purpose::STANDARD.encode(&bytes[..cap]);
        return Ok(Response::FsRead {
            content: Some(content),
            hash,
            truncated,
            kind,
        });
    }

    let text = String::from_utf8_lossy(&bytes).into_owned();
    let cap = crate::text::floor_char_boundary(&text, FS_TEXT_READ_BYTE_CAP.min(text.len()));
    let truncated = text.len() > cap;
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

/// Return every daemon-discovered settings layer. Each snapshot carries an
/// ephemeral capability bound to this canonical trusted root, exact target,
/// raw revision, and individual denylist occurrences.
pub async fn get_extended_config_snapshot(
    ctx: &crate::daemon::server::DaemonContext,
    project_root: String,
    owner: String,
) -> Result<Response, ErrorPayload> {
    let root = trusted_settings_root(ctx, &project_root).await?;
    join_fs_handler(
        "get_extended_config_snapshot",
        tokio::task::spawn_blocking(move || {
            let mut layers = Vec::new();
            let now = Instant::now();
            settings_capabilities()
                .lock().map_err(|_| internal("settings capability registry lock poisoned"))?
                .retain(|_, cap| cap.expires_at > now);
            for (kind, target) in discovered_settings_layers(&root)? {
                let guard = cockpit_config::config::hold_config_mutation_lock(&target)
                    .map_err(internal)?;
                let (raw, identity) = read_optional_config(&target)?;
                let revision = content_hash(&raw);
                let mut config: cockpit_config::config::extended::ExtendedConfig =
                    serde_json::from_slice(&raw).map_err(bad_request_config)?;
                let denylist_ids: Vec<String> = config
                    .redact
                    .denylist
                    .iter()
                    .map(|_| Uuid::new_v4().to_string())
                    .collect();
                let denylist = config
                    .redact
                    .denylist
                    .iter()
                    .zip(&denylist_ids)
                    .map(|(value, id)| redacted_denylist_entry(id, value))
                    .collect();
                config.redact.denylist.clear();
                config.image_generation = config.image_generation.redacted_for_snapshot();
                let id = Uuid::new_v4();
                drop(guard);
                settings_capabilities()
                    .lock().map_err(|_| internal("settings capability registry lock poisoned"))?
                    .insert(id, SettingsCapability {
                    owner: owner.clone(), root: root.clone(), target: target.clone(),
                    revision: revision.clone(), identity, denylist_ids, issued_at: now,
                    expires_at: now + SETTINGS_CAPABILITY_TTL,
                });
                enforce_settings_capability_caps(&owner)?;
                layers.push(cockpit_proto::ExtendedConfigLayerSnapshot {
                    layer_id: id.to_string(), kind,
                    display_path: target.display().to_string(), config: Box::new(config),
                    denylist, revision,
                });
            }
            Ok(Response::ExtendedConfigSnapshot { layers,
                config_generation: crate::daemon::server::inventory::current_config_generation() })
        }),
    )
    .await
}

/// Apply a client-generated JSON merge patch under the daemon's config lock.
/// Unknown and secret-bearing keys absent from the patch remain byte-for-byte
/// represented in the parsed document; the final typed render validates all
/// known settings and preserves the daemon-owned image registry.
pub async fn apply_extended_config_patch(
    ctx: &crate::daemon::server::DaemonContext,
    project_root: String,
    layer_id: String,
    patch: cockpit_proto::ExtendedConfigPatch,
    expected_revision: String,
    owner: String,
) -> Result<Response, ErrorPayload> {
    let root = trusted_settings_root(ctx, &project_root).await?;
    join_fs_handler(
        "apply_extended_config_patch",
        tokio::task::spawn_blocking(move || {
            let id = Uuid::parse_str(&layer_id)
                .map_err(|_| conflict("settings snapshot is absent, expired, or stale"))?;
            let capability = {
                let mut caps = settings_capabilities().lock().map_err(|_| internal("settings capability registry lock poisoned"))?;
                let now = Instant::now();
                caps.retain(|_, cap| cap.expires_at > now);
                caps.get(&id).cloned()
                    .ok_or_else(|| conflict("settings snapshot is absent, expired, or stale"))?
            };
            if capability.owner != owner
                || capability.root != root
                || capability.revision != expected_revision
            {
                return Err(conflict("settings snapshot is absent, expired, or stale"));
            }
            let target = capability.target;
            let _guard =
                cockpit_config::config::hold_config_mutation_lock(&target).map_err(internal)?;
            let (raw, identity) = read_optional_config(&target)?;
            let existed = identity.is_some();
            if identity != capability.identity {
                return Err(conflict("configuration file identity changed since snapshot"));
            }
            let materialize = patch.materialize;
            let current_hash = content_hash(&raw);
            if current_hash != expected_revision {
                return Err(ErrorPayload {
                    code: ErrorCode::HashMismatch,
                    message: format!(
                        "configuration changed before patch; current revision is {current_hash}"
                    ),
                });
            }
            let mut document: serde_json::Value =
                serde_json::from_slice(&raw).map_err(bad_request_config)?;
            let current_typed: cockpit_config::config::extended::ExtendedConfig =
                serde_json::from_slice(&raw).map_err(bad_request_config)?;
            let current_typed = serde_json::to_value(current_typed).map_err(internal)?;
            let candidate = serde_json::to_value(&patch.candidate).map_err(internal)?;
            let object = document.as_object_mut().ok_or_else(|| {
                bad_request("extended config root must be a JSON object")
            })?;
            let candidate = candidate.as_object().expect("ExtendedConfig serializes as object");
            let current_typed = current_typed.as_object()
                .expect("ExtendedConfig serializes as object");
            for field in patch.fields {
                if field == cockpit_proto::ExtendedConfigField::ImageGeneration {
                    return Err(bad_request(
                        "image generation settings require the dedicated daemon API",
                    ));
                }
                let key = field.json_key();
                let value = candidate.get(key).cloned().ok_or_else(|| {
                    bad_request(format!("typed settings candidate omitted `{key}`"))
                })?;
                let current = current_typed.get(key).ok_or_else(|| {
                    bad_request(format!("typed settings schema omitted `{key}`"))
                })?;
                if field == cockpit_proto::ExtendedConfigField::Redact {
                    let existing = object
                        .get("redact")
                        .and_then(serde_json::Value::as_object)
                        .and_then(|redact| redact.get("denylist"))
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!([]));
                    let mut value = value;
                    value.as_object_mut().expect("RedactConfig serializes as object")
                        .insert("denylist".into(), existing.clone());
                    let mut current = current.clone();
                    current.as_object_mut().expect("RedactConfig serializes as object")
                        .insert("denylist".into(), existing.clone());
                    merge_changed_known_value(
                        object.entry(key).or_insert(serde_json::Value::Null), &current, value);
                } else {
                    merge_changed_known_value(
                        object.entry(key).or_insert(serde_json::Value::Null), current, value);
                }
            }
            apply_denylist_mutations(object, patch.denylist, &capability.denylist_ids)?;
            let patched = serde_json::to_vec_pretty(&document).map_err(internal)?;
            let merged = cockpit_config::config::extended::render_saved_extended_config_preserving_image_generation(
                &patched,
                &raw,
            )
            .map_err(bad_request_config)?;
            let desired_hash = content_hash(&merged);
            let config_generation = if desired_hash != current_hash || (materialize && !existed) {
                // Re-open immediately before publication while the real
                // per-target cross-process lock is held. Both identity and
                // bytes must still describe the exact capability snapshot.
                let (precommit, precommit_identity) = read_optional_config(&target)?;
                if precommit_identity != capability.identity
                    || content_hash(&precommit) != expected_revision
                {
                    return Err(conflict(
                        "configuration target changed immediately before commit",
                    ));
                }
                cockpit_config::config::write_config_bytes_atomic(&target, &merged)
                    .map_err(internal)?;
                crate::daemon::server::inventory::publish_committed_config_generation()
            } else {
                crate::daemon::server::inventory::current_config_generation()
            };
            settings_capabilities()
                .lock().map_err(|_| internal("settings capability registry lock poisoned"))?
                .remove(&id);
            Ok(Response::ExtendedConfigSaved { hash: desired_hash, config_generation })
        }),
    )
    .await
}

async fn trusted_settings_root(
    ctx: &DaemonContext,
    project_root: &str,
) -> Result<PathBuf, ErrorPayload> {
    let root = canonical_project_root(project_root)?;
    let policy = crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &root)
        .await
        .map_err(|error| ErrorPayload {
            code: ErrorCode::PermissionDenied,
            message: format!("workspace trust is required for settings mutation: {error:#}"),
        })?;
    if policy.mode != crate::db::workspace_trust::WorkspaceTrustMode::Trust {
        return Err(ErrorPayload {
            code: ErrorCode::PermissionDenied,
            message: "settings mutation requires a trusted workspace".into(),
        });
    }
    Ok(root)
}

fn discovered_settings_layers(root: &Path) -> Result<Vec<(cockpit_proto::CockpitConfigLayer, PathBuf)>, ErrorPayload> {
    use cockpit_config::config::dirs::{ConfigDirKind as K, CONFIG_FILE};
    let mut layer_dirs = cockpit_config::config::dirs::discover_config_dirs(root);
    if let Some(home) = dirs::home_dir() {
        layer_dirs.push(cockpit_config::config::dirs::ConfigDir { kind: K::HomeXdg, path: home.join(".config/cockpit") });
        layer_dirs.push(cockpit_config::config::dirs::ConfigDir { kind: K::HomeDot, path: home.join(".cockpit") });
    }
    layer_dirs.push(cockpit_config::config::dirs::ConfigDir {
        kind: K::MachineLocal,
        path: cockpit_config::config::dirs::local_config_dir_for(root).map_err(internal)?,
    });
    layer_dirs.push(cockpit_config::config::dirs::ConfigDir { kind: K::Project, path: root.join(".cockpit") });
    let mut seen = std::collections::HashSet::new();
    Ok(layer_dirs.into_iter().filter_map(|dir| {
        let target = dir.path.join(CONFIG_FILE);
        if !seen.insert(target.clone()) { return None; }
        let kind = match dir.kind { K::HomeXdg => cockpit_proto::CockpitConfigLayer::HomeXdg,
            K::HomeDot => cockpit_proto::CockpitConfigLayer::HomeDot,
            K::MachineLocal => cockpit_proto::CockpitConfigLayer::MachineLocal,
            K::Project => cockpit_proto::CockpitConfigLayer::Project };
        Some((kind, target))
    }).collect())
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
    Ok(match cockpit_config::config::read_config_file_nofollow_with_identity(target)
        .map_err(internal)?
    {
        Some((bytes, identity)) => (bytes, Some(identity)),
        None => (b"{}\n".to_vec(), None),
    })
}

fn enforce_settings_capability_caps(owner: &str) -> Result<(), ErrorPayload> {
    let mut caps = settings_capabilities()
        .lock()
        .map_err(|_| internal("settings capability registry lock poisoned"))?;
    while caps.values().filter(|cap| cap.owner == owner).count()
        > SETTINGS_CAPABILITY_OWNER_CAP
    {
        let oldest = caps
            .iter()
            .filter(|(_, cap)| cap.owner == owner)
            .min_by_key(|(_, cap)| cap.issued_at)
            .map(|(id, _)| *id);
        if let Some(id) = oldest { caps.remove(&id); } else { break; }
    }
    while caps.len() > SETTINGS_CAPABILITY_GLOBAL_CAP {
        let oldest = caps.iter().min_by_key(|(_, cap)| cap.issued_at).map(|(id, _)| *id);
        if let Some(id) = oldest { caps.remove(&id); } else { break; }
    }
    Ok(())
}

fn redacted_denylist_entry(id: &str, value: &str) -> cockpit_proto::RedactedDenylistEntry {
    cockpit_proto::RedactedDenylistEntry {
        entry_id: id.to_owned(),
        fingerprint: id.chars().take(8).collect(),
        display_mask: format!("•••• ({} bytes)", value.len()),
    }
}

fn merge_changed_known_value(
    target: &mut serde_json::Value,
    current: &serde_json::Value,
    candidate: serde_json::Value,
) {
    if current == &candidate {
        return;
    }
    match (target, current, candidate) {
        (serde_json::Value::Object(target), serde_json::Value::Object(current), serde_json::Value::Object(candidate)) => {
            for (key, value) in candidate {
                if let Some(current) = current.get(&key) {
                    merge_changed_known_value(
                        target.entry(key).or_insert(serde_json::Value::Null), current, value);
                }
            }
        }
        (target, _, candidate) => *target = candidate,
    }
}

fn apply_denylist_mutations(
    document: &mut serde_json::Map<String, serde_json::Value>,
    mutations: Vec<cockpit_proto::DenylistMutation>,
    occurrence_ids: &[String],
) -> Result<(), ErrorPayload> {
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
    let mut values: Vec<(String, String)> = values
        .iter()
        .zip(occurrence_ids)
        .map(|(value, id)| {
            value
                .as_str()
                .map(|value| (id.clone(), value.to_owned()))
                .ok_or_else(|| bad_request("redact.denylist entries must be strings"))
        })
        .collect::<Result<_, _>>()?;
    let locate = |values: &[(String, String)], id: &str| {
        values.iter().position(|(entry_id, _)| entry_id == id)
    };
    for mutation in mutations {
        match mutation {
            cockpit_proto::DenylistMutation::Add { value, after_id } => {
                validate_new_denylist_literal(&value)?;
                let index = match after_id {
                    Some(id) => {
                        locate(&values, &id)
                            .ok_or_else(|| conflict("denylist entry changed since snapshot"))?
                            + 1
                    }
                    None => 0,
                };
                values.insert(index, (Uuid::new_v4().to_string(), value));
            }
            cockpit_proto::DenylistMutation::Update { entry_id, value } => {
                validate_new_denylist_literal(&value)?;
                let index = locate(&values, &entry_id)
                    .ok_or_else(|| conflict("denylist entry changed since snapshot"))?;
                values[index].1 = value;
            }
            cockpit_proto::DenylistMutation::Remove { entry_id } => {
                let index = locate(&values, &entry_id)
                    .ok_or_else(|| conflict("denylist entry changed since snapshot"))?;
                values.remove(index);
            }
            cockpit_proto::DenylistMutation::Move { entry_id, after_id } => {
                let index = locate(&values, &entry_id)
                    .ok_or_else(|| conflict("denylist entry changed since snapshot"))?;
                let value = values.remove(index);
                let target = match after_id {
                    Some(id) => {
                        locate(&values, &id)
                            .ok_or_else(|| conflict("denylist entry changed since snapshot"))?
                            + 1
                    }
                    None => 0,
                };
                values.insert(target, value);
            }
        }
    }
    redact.insert(
        "denylist".into(),
        serde_json::Value::Array(
            values
                .into_iter()
                .map(|(_, value)| serde_json::Value::String(value))
                .collect(),
        ),
    );
    Ok(())
}

fn validate_new_denylist_literal(value: &str) -> Result<(), ErrorPayload> {
    if value.is_empty() || value.len() > 64 * 1024 || value.contains('\0') {
        return Err(bad_request("denylist literal is invalid"));
    }
    if value.starts_with("•••• (") && value.ends_with(" bytes)") {
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
    // (EACCES/EIO/EMFILE/…) must NOT be coerced to empty: the merge would then
    // find no on-disk `image_generation` to preserve and the atomic write would
    // WIPE the registry — the exact data loss this path exists to prevent. Fail
    // closed instead, writing nothing.
    let current = match std::fs::read(&target) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(internal(error)),
    };
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
    let desired_hash = content_hash(&merged);
    let config_generation = if desired_hash != current_hash {
        cockpit_config::config::write_config_bytes_atomic(&target, &merged).map_err(internal)?;
        crate::daemon::server::inventory::publish_committed_config_generation()
    } else {
        crate::daemon::server::inventory::current_config_generation()
    };
    Ok(Response::ExtendedConfigSaved {
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
    let current = match std::fs::read(&target) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(err) => return Err(internal(err)),
    };
    let current_hash = content_hash(&current);
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

    let current = match std::fs::read(&target) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(err) => return Err(internal(err)),
    };
    let current_hash = content_hash(&current);
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
    let cap = crate::text::floor_char_boundary(
        &outcome.stdout,
        FS_TEXT_READ_BYTE_CAP.min(outcome.stdout.len()),
    );
    Ok(Response::GitDiffFile {
        diff: outcome.stdout[..cap].to_string(),
        truncated: outcome.stdout.len() > cap,
    })
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
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
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
    use crate::daemon::principal::{ClientPrincipal, PrincipalGrant, PrincipalScope};

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
        assert!(secret_blocked_for_sharee(&ctx, &remote_project_files(root), root, &path).unwrap());
        assert!(!secret_blocked_for_sharee(&ctx, &ClientPrincipal::owner(), root, &path).unwrap());
    }

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
        assert!(matches!(resp, Response::ExtendedConfigSaved { .. }));

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
}
