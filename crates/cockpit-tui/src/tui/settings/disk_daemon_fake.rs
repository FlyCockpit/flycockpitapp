//! Disk-backed test double for the daemon's settings and agent contract.
//!
//! Unit reducers run the same production code paths the TUI runs, so they
//! issue the same daemon RPCs. This module answers those RPCs against the real
//! filesystem and synthesizes wire-valid responses: opaque authority tokens
//! (64 lowercase hex), layer capabilities, revisions, projection digests, and
//! commit receipts all satisfy the client-side validators in [`super`],
//! [`super::agents_page`], `goal_settings_pane`, and `tools_pane` by
//! construction.
//!
//! Only transport and daemon-side bookkeeping are faked. Every observable
//! effect — which file is written, which override is removed, what the next
//! snapshot reports — comes from the same `cockpit_config`/`cockpit_core`
//! primitives the daemon itself uses, so tests keep asserting on real disk
//! state.
//!
//! Deliberate divergences from the daemon, none of which weaken a client-side
//! check:
//!   - tokens are domain-separated SHA-256 digests rather than process-keyed
//!     HMACs; only the format and internal consistency are contractual,
//!   - there is no workspace-trust gate, no redaction table (so settings and
//!     provider projections carry their authored values — the MCP projection
//!     IS owner-view redacted, through the shared
//!     `cockpit_core::mcp::config::redact_config_for_owner_view`), no
//!     capability TTL, and no reset-all journal,
//!   - `SaveMcpConfig` restores redaction sentinels like the daemon (shared
//!     helper) but has no secret vault, so credential-bearing mutations fail
//!     closed,
//!   - file-identity CAS is reduced to content CAS.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use cockpit_config::extended::ExtendedConfig;
use cockpit_core::agents::{AgentKind, BUILTIN_AGENT_NAMES};
use cockpit_proto::{
    AgentEditSnapshot, AgentEditTarget, AgentEditorCompletion, AgentEditorLease,
    AgentEditorSettlementStatus, AgentEntryKind, AgentInventoryEntry, AgentMutation,
    AgentMutationOutcome, AgentMutationResult, AgentSourceLayer, CockpitConfigLayer,
    CommittedDenylistEntry, ConfigCommitStatus, ConfigPublicationStatus, DesiredDenylistEntry,
    ExtendedConfigField, ExtendedConfigLayerSnapshot, ExtendedConfigPatch,
    ExtendedConfigPathMutation, RedactedDenylistEntry, Request, Response,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::SettingsDaemonEffect;

/// The daemon rejects a mutation whose snapshot no longer exists with one
/// indistinguishable message; the TUI surfaces it verbatim.
const STALE_SNAPSHOT: &str = "settings snapshot is absent, expired, or stale";

const EDITOR_LEASE_TTL_MS: i64 = 8 * 60 * 60 * 1_000;

/// Restoring a redacted occurrence needs the daemon's redaction table, which
/// this fake has no equivalent of; a patch that carries one fails loudly
/// rather than silently dropping the mutation.
const UNSUPPORTED_REDACTED_MUTATIONS: &str =
    "the disk-backed test daemon fake does not implement redacted occurrence mutations";

const READ_ONLY_DIRECTORY_AGENT: &str =
    "directory-form agents are read-only in the settings editor";

const INVALID_AGENT_DIAGNOSTIC: &str =
    "agent definition is invalid; inspect it through the daemon editor";

/// Shared fake used whenever a test has not installed its own transport.
pub(crate) fn default_effect() -> Arc<dyn SettingsDaemonEffect> {
    static EFFECT: OnceLock<Arc<DiskDaemonFake>> = OnceLock::new();
    EFFECT.get_or_init(|| Arc::new(DiskDaemonFake)).clone()
}

/// Make one `config.json` visible to settings snapshots even though daemon-style
/// layer discovery cannot reach it.
///
/// `config_layer_request` resolves a snapshot's project root from the dialog's
/// active root (or the process cwd), never from the edited path, so a fixture
/// whose config lives in a temporary directory outside every discovered layer
/// is invisible to the fake. Registering it restores the layer the fixture
/// expects without loosening any authority check: the registered target is
/// snapshotted, revisioned, and patched exactly like a discovered one.
pub(crate) fn register_settings_layer_target(target: &Path) {
    if let Ok(mut targets) = extra_layer_targets().lock() {
        targets.insert(target.to_path_buf());
    }
}

pub(crate) struct DiskDaemonFake;

impl SettingsDaemonEffect for DiskDaemonFake {
    fn request(&self, request: Request) -> Result<Response, String> {
        match request {
            Request::GetExtendedConfigSnapshot {
                project_root,
                snapshot_session_id,
            } => extended_config_snapshot(Path::new(&project_root), &snapshot_session_id),
            Request::ApplyExtendedConfigPatch {
                project_root,
                layer_id,
                patch,
                expected_revision,
                snapshot_session_id,
                ..
            } => apply_extended_config_patch(
                Path::new(&project_root),
                &layer_id,
                patch,
                &expected_revision,
                &snapshot_session_id,
            ),
            Request::GetProviderCatalogSnapshot {
                project_root,
                provider_id,
                snapshot_session_id,
            } => provider_catalog_snapshot(
                Path::new(&project_root),
                provider_id.as_deref(),
                &snapshot_session_id,
            ),
            Request::SaveMcpConfig {
                client_operation_id,
                project_root,
                snapshot_capability,
                owner_root,
                config_path,
                expected_revision,
                mutation_intent_hash,
                patch,
                secret_values_json,
                target_scope: _,
            } => save_mcp_config(
                &client_operation_id,
                Path::new(&project_root),
                &snapshot_capability,
                &owner_root,
                &config_path,
                &expected_revision,
                &mutation_intent_hash,
                &patch,
                &secret_values_json,
            ),
            Request::GetAgentInventory { project_root } => {
                agent_inventory(Path::new(&project_root))
            }
            Request::GetAgentEditSnapshot { project_root, name } => {
                agent_edit_snapshot(Path::new(&project_root), &name)
                    .map(Response::AgentEditSnapshot)
            }
            Request::MutateAgent {
                client_operation_id,
                mutation_intent_hash,
                project_root,
                mutation,
                expected_revision,
            } => mutate_agent(
                client_operation_id,
                mutation_intent_hash,
                Path::new(&project_root),
                mutation,
                expected_revision,
            )
            .map(Response::AgentMutated),
            Request::BeginAgentEditorLease {
                client_operation_id,
                project_root,
                name,
                expected_revision,
            } => begin_editor_lease(
                client_operation_id,
                Path::new(&project_root),
                &name,
                expected_revision,
            ),
            Request::CompleteAgentEditorLease {
                client_operation_id,
                project_root,
                lease_id,
                markdown,
            } => complete_editor_lease(
                client_operation_id,
                Path::new(&project_root),
                &lease_id,
                markdown,
            ),
            // The assistant registry lives in the daemon database, so the disk
            // fake projects an empty registry and refuses every mutation rather
            // than inventing registry rows a test could not have created.
            Request::ListAssistants => Ok(Response::Assistants {
                assistants: Vec::new(),
                config_generation: 0,
            }),
            Request::SaveAssistantDefinition { .. }
            | Request::UpsertAssistant { .. }
            | Request::DeleteAssistant { .. } => Err(
                "assistant registry mutations are unavailable in the disk-backed test daemon fake"
                    .to_string(),
            ),
            other => Err(format!(
                "the disk-backed test daemon fake does not handle `{}`",
                request_label(&other)
            )),
        }
    }
}

fn request_label(request: &Request) -> String {
    serde_json::to_value(request)
        .ok()
        .and_then(|value| {
            value
                .get("request")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unknown request".to_string())
}

// ── Process-local daemon bookkeeping ────────────────────────────────────────

/// One issued settings-layer capability. A capability is bound to the exact
/// root, snapshot session, target, and on-disk bytes it was minted from.
#[derive(Clone)]
struct LayerCapability {
    root: PathBuf,
    session: String,
    target: PathBuf,
    kind: CockpitConfigLayer,
    revision: String,
    raw_revision: String,
    denylist_ids: Vec<String>,
}

#[derive(Clone)]
struct EditorLease {
    root: PathBuf,
    name: String,
    revision: String,
}

fn layer_capabilities() -> &'static Mutex<HashMap<Uuid, LayerCapability>> {
    static CAPABILITIES: OnceLock<Mutex<HashMap<Uuid, LayerCapability>>> = OnceLock::new();
    CAPABILITIES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn editor_leases() -> &'static Mutex<HashMap<String, EditorLease>> {
    static LEASES: OnceLock<Mutex<HashMap<String, EditorLease>>> = OnceLock::new();
    LEASES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn extra_layer_targets() -> &'static Mutex<BTreeSet<PathBuf>> {
    static TARGETS: OnceLock<Mutex<BTreeSet<PathBuf>>> = OnceLock::new();
    TARGETS.get_or_init(|| Mutex::new(BTreeSet::new()))
}

static CONFIG_GENERATION: AtomicU64 = AtomicU64::new(1);

fn current_config_generation() -> u64 {
    CONFIG_GENERATION.load(Ordering::SeqCst)
}

/// Publishing a committed mutation advances the generation by exactly one, the
/// step the settings receipt guard accepts.
fn publish_config_generation() -> u64 {
    CONFIG_GENERATION
        .fetch_add(1, Ordering::SeqCst)
        .wrapping_add(1)
}

fn poisoned(what: &str) -> String {
    format!("the disk-backed test daemon fake lost its {what} registry")
}

// ── Authority tokens ────────────────────────────────────────────────────────

fn hex(bytes: &[u8]) -> String {
    cockpit_core::intel::hex_lower(bytes)
}

fn content_hash(bytes: &[u8]) -> String {
    hex(Sha256::digest(bytes).as_slice())
}

/// Length-prefixed, domain-separated digest. The daemon mints the same shapes
/// with a process-keyed HMAC; only the opaque format and per-field
/// unambiguity matter to a client.
fn mint(domain: &[u8], fields: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"cockpit-disk-daemon-fake-token-v1\0");
    digest.update((domain.len() as u64).to_le_bytes());
    digest.update(domain);
    for field in fields {
        digest.update((field.len() as u64).to_le_bytes());
        digest.update(field);
    }
    hex(digest.finalize().as_slice())
}

fn settings_revision(kind: CockpitConfigLayer, target: &Path, raw_revision: &str) -> String {
    mint(
        b"settings-layer-revision/v1",
        &[
            &[kind as u8],
            target.as_os_str().as_encoded_bytes(),
            raw_revision.as_bytes(),
        ],
    )
}

fn denylist_occurrence_id(
    kind: CockpitConfigLayer,
    target: &Path,
    revision: &str,
    index: usize,
    value: &str,
) -> String {
    mint(
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

fn definition_revision(
    name: &str,
    source_layer: AgentSourceLayer,
    source_identity: &str,
    source_content_hash: &str,
    target_exists: bool,
) -> String {
    mint(
        b"agent-definition-revision/v1",
        &[
            name.as_bytes(),
            &[source_layer as u8],
            source_identity.as_bytes(),
            source_content_hash.as_bytes(),
            &[u8::from(target_exists)],
        ],
    )
}

fn embedded_source_identity(root: &Path, name: &str, content: &[u8]) -> String {
    mint(
        b"agent-source/embedded/v1",
        &[
            root.as_os_str().as_encoded_bytes(),
            name.as_bytes(),
            content,
        ],
    )
}

/// Bind the identity to the exact filesystem object, so a rewritten override
/// mints a new revision even when its bytes are unchanged.
fn opaque_source_identity(
    root: &Path,
    source: &Path,
    layer: AgentSourceLayer,
    content: &[u8],
) -> Result<String, String> {
    let metadata = std::fs::symlink_metadata(source)
        .map_err(|error| format!("agent management failed: {error}"))?;
    if metadata.file_type().is_symlink() {
        return Err("agent source became a symlink while minting its identity".to_string());
    }
    let mut platform_identity = Vec::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        platform_identity.extend_from_slice(&metadata.dev().to_le_bytes());
        platform_identity.extend_from_slice(&metadata.ino().to_le_bytes());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        platform_identity.extend_from_slice(&metadata.file_attributes().to_le_bytes());
        platform_identity.extend_from_slice(&metadata.creation_time().to_le_bytes());
        platform_identity.extend_from_slice(&metadata.last_write_time().to_le_bytes());
    }
    Ok(mint(
        b"agent-source/file/v1",
        &[
            &[layer as u8],
            root.as_os_str().as_encoded_bytes(),
            source.as_os_str().as_encoded_bytes(),
            content,
            &metadata.len().to_le_bytes(),
            &platform_identity,
        ],
    ))
}

fn inventory_revision(entries: &[AgentInventoryEntry]) -> String {
    let mut ordered = entries.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.name.cmp(&right.name));
    let mut canonical = Vec::new();
    for entry in ordered {
        for value in [&entry.name, &entry.source_identity, &entry.revision] {
            canonical.extend_from_slice(&(value.len() as u64).to_le_bytes());
            canonical.extend_from_slice(value.as_bytes());
        }
        canonical.extend_from_slice(&[
            entry.kind as u8,
            u8::from(entry.overridden),
            u8::from(entry.editable),
        ]);
    }
    mint(b"agent-inventory-revision/v1", &[&canonical])
}

// ── Settings layers ─────────────────────────────────────────────────────────

fn layer_kind(root: &Path, target: &Path) -> CockpitConfigLayer {
    let Some(directory) = target.parent() else {
        return CockpitConfigLayer::Project;
    };
    if let Some(home) = dirs::home_dir() {
        if directory == home.join(".config/cockpit") {
            return CockpitConfigLayer::HomeXdg;
        }
        if directory == home.join(".cockpit") {
            return CockpitConfigLayer::HomeDot;
        }
    }
    if cockpit_config::dirs::local_config_dir_for(root)
        .is_ok_and(|local| local.as_path() == directory)
    {
        return CockpitConfigLayer::MachineLocal;
    }
    CockpitConfigLayer::Project
}

/// Every `config.json` the daemon would discover for `root`, plus the
/// `COCKPIT_CONFIG` pin and any fixture target registered through
/// [`register_settings_layer_target`]. Targets that do not exist yet are
/// included: a snapshot of an absent layer is what lets `materialize` create
/// it.
fn discovered_layer_targets(root: &Path) -> Vec<(CockpitConfigLayer, PathBuf)> {
    use cockpit_config::dirs::CONFIG_FILE;
    let mut candidates = Vec::new();
    for directory in cockpit_config::dirs::discover_config_dirs(root) {
        candidates.push(directory.path.join(CONFIG_FILE));
    }
    if let Some(home) = dirs::home_dir() {
        candidates.push(home.join(".config/cockpit").join(CONFIG_FILE));
        candidates.push(home.join(".cockpit").join(CONFIG_FILE));
    }
    if let Ok(local) = cockpit_config::dirs::local_config_dir_for(root) {
        candidates.push(local.join(CONFIG_FILE));
    }
    candidates.push(root.join(".cockpit").join(CONFIG_FILE));
    candidates.extend(cockpit_config::dirs::config_file_paths_for_load(root));
    if let Ok(targets) = extra_layer_targets().lock() {
        candidates.extend(targets.iter().cloned());
    }
    let mut seen = HashSet::new();
    candidates
        .into_iter()
        .filter(|target| seen.insert(target.clone()))
        .map(|target| (layer_kind(root, &target), target))
        .collect()
}

/// Whether a discovered layer belongs to the test that asked for the snapshot:
/// it lives under the requested project root, or a fixture registered it.
///
/// Enumeration also reaches the developer's own home, XDG, and machine-local
/// layers. Those are snapshotted for fidelity but are not part of any fixture,
/// so an unreadable or malformed one is skipped instead of failing every
/// settings test on the machine. A requested layer stays strict.
fn is_requested_layer(root: &Path, target: &Path) -> bool {
    target.starts_with(root)
        || extra_layer_targets()
            .lock()
            .is_ok_and(|targets| targets.contains(target))
}

/// Missing layers read as the empty document, exactly as the daemon reports
/// them, so an absent config still has a stable revision to patch against.
fn read_optional_config(target: &Path) -> Result<(Vec<u8>, bool), String> {
    match cockpit_config::config::read_config_file_nofollow(target)
        .map_err(|error| format!("reading {}: {error}", target.display()))?
    {
        Some(bytes) => Ok((bytes, true)),
        None => Ok((b"{}\n".to_vec(), false)),
    }
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
            if ExtendedConfigField::from_json_key(key).is_none() {
                continue;
            }
            let mut path = vec![key.clone()];
            visit(value, &mut path, &mut out);
        }
    }
    out.sort();
    out
}

fn extended_config_snapshot(root: &Path, session: &str) -> Result<Response, String> {
    let mut layers = Vec::new();
    let mut pending = Vec::new();
    for (kind, target) in discovered_layer_targets(root) {
        let requested = is_requested_layer(root, &target);
        let raw = match read_optional_config(&target) {
            Ok((raw, _)) => raw,
            Err(_) if !requested => continue,
            Err(error) => return Err(error),
        };
        let raw_revision = content_hash(&raw);
        let revision = settings_revision(kind, &target, &raw_revision);
        let raw_document: serde_json::Value = match serde_json::from_slice(&raw) {
            Ok(document) => document,
            Err(_) if !requested => continue,
            Err(error) => {
                return Err(format!(
                    "settings layer {} is not a valid JSON document: {error}",
                    target.display()
                ));
            }
        };
        let authored_paths = authored_typed_paths(&raw_document);
        let mut config: ExtendedConfig = match serde_json::from_slice(&raw) {
            Ok(config) => config,
            Err(_) if !requested => continue,
            Err(error) => {
                return Err(format!(
                    "settings layer {} is not a valid settings document: {error}",
                    target.display()
                ));
            }
        };
        let denylist_ids = config
            .redact
            .denylist
            .iter()
            .enumerate()
            .map(|(index, value)| denylist_occurrence_id(kind, &target, &revision, index, value))
            .collect::<Vec<_>>();
        let denylist = denylist_ids
            .iter()
            .map(|entry_id| RedactedDenylistEntry {
                entry_id: entry_id.clone(),
                display_mask: cockpit_proto::REDACTED_DENYLIST_MASK.to_string(),
            })
            .collect();
        // Denylist literals only ever leave the daemon as opaque occurrences,
        // and the image registry has its own dedicated API.
        config.redact.denylist.clear();
        config.image_generation = config.image_generation.redacted_for_snapshot();
        let id = Uuid::new_v4();
        pending.push((
            id,
            LayerCapability {
                root: root.to_path_buf(),
                session: session.to_string(),
                target: target.clone(),
                kind,
                revision: revision.clone(),
                raw_revision,
                denylist_ids,
            },
        ));
        layers.push(ExtendedConfigLayerSnapshot {
            layer_id: id.to_string(),
            kind,
            display_path: target.display().to_string(),
            config: Box::new(config),
            denylist,
            revision,
            authored_paths,
        });
    }
    let mut capabilities = layer_capabilities()
        .lock()
        .map_err(|_| poisoned("settings capability"))?;
    // A refresh replaces the prior group for this root/session rather than
    // accumulating capabilities beside it.
    capabilities
        .retain(|_, capability| !(capability.root == root && capability.session == session));
    capabilities.extend(pending);
    Ok(Response::ExtendedConfigSnapshot {
        layers,
        config_generation: current_config_generation(),
    })
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
) -> Result<(), String> {
    let (leaf, parents) = path
        .split_last()
        .ok_or_else(|| "settings path cannot be empty".to_string())?;
    let mut cursor = root;
    for key in parents {
        if !cursor.is_object() {
            return Err("settings path crosses a non-object value".to_string());
        }
        cursor = cursor
            .as_object_mut()
            .expect("checked object")
            .entry(key.clone())
            .or_insert_with(|| serde_json::json!({}));
    }
    cursor
        .as_object_mut()
        .ok_or_else(|| "settings path parent is not an object".to_string())?
        .insert(leaf.clone(), value);
    Ok(())
}

fn unset_object_path(root: &mut serde_json::Value, path: &[String]) -> Result<(), String> {
    let (leaf, parents) = path
        .split_last()
        .ok_or_else(|| "settings path cannot be empty".to_string())?;
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
    match cursor.as_object_mut() {
        Some(object) => {
            object.remove(leaf);
            Ok(())
        }
        None => Err("settings path parent is not an object".to_string()),
    }
}

fn validate_new_denylist_literal(value: &str) -> Result<(), String> {
    // Align with `MAX_SENSITIVE_FRAME_BYTES` (16 KiB): the wire type
    // `SensitiveWireLiteral` enforces this cap at deserialization.  Keeping
    // the validator at the same bound gives one consistent failure mode.
    if value.is_empty()
        || value.len() > cockpit_proto::MAX_SENSITIVE_FRAME_BYTES
        || value.contains('\0')
    {
        return Err("denylist literal is invalid".to_string());
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
        return Err("redacted denylist display masks are not accepted as literals".to_string());
    }
    Ok(())
}

/// Rewrite `redact.denylist` from the desired occurrence sequence, returning
/// `(consumed occurrence id, client nonce, literal)` per committed entry.
fn apply_denylist_sequence(
    document: &mut serde_json::Map<String, serde_json::Value>,
    desired: Vec<DesiredDenylistEntry>,
    occurrence_ids: &[String],
) -> Result<Vec<(String, Option<String>, String)>, String> {
    let redact = document
        .entry("redact")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or_else(|| "redact settings must be an object".to_string())?;
    let values = redact
        .entry("denylist")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .ok_or_else(|| "redact.denylist must be an array".to_string())?;
    let values: Vec<(String, String)> = values
        .iter()
        .zip(occurrence_ids)
        .map(|(value, id)| {
            value
                .as_str()
                .map(|value| (id.clone(), value.to_owned()))
                .ok_or_else(|| "redact.denylist entries must be strings".to_string())
        })
        .collect::<Result<_, _>>()?;
    if values.len() != occurrence_ids.len() {
        return Err("denylist occurrences changed since snapshot".to_string());
    }
    let by_id = values.iter().cloned().collect::<HashMap<String, String>>();
    let mut used = HashSet::new();
    let mut nonces = HashSet::new();
    let mut result = Vec::with_capacity(desired.len());
    for entry in desired {
        match entry {
            DesiredDenylistEntry::Existing { entry_id } => {
                if !used.insert(entry_id.clone()) {
                    return Err("a denylist occurrence may appear exactly once".to_string());
                }
                let value = by_id
                    .get(&entry_id)
                    .cloned()
                    .ok_or_else(|| "denylist entry changed since snapshot".to_string())?;
                result.push((entry_id, None, value));
            }
            DesiredDenylistEntry::New {
                client_nonce,
                literal,
            } => {
                let canonical = Uuid::parse_str(&client_nonce)
                    .is_ok_and(|nonce| nonce.to_string() == client_nonce);
                if !canonical || !nonces.insert(client_nonce.clone()) {
                    return Err(
                        "new denylist occurrence nonce is invalid or duplicated".to_string()
                    );
                }
                validate_new_denylist_literal(literal.as_str())?;
                result.push((
                    String::new(),
                    Some(client_nonce),
                    literal.as_str().to_owned(),
                ));
            }
        }
    }
    redact.insert(
        "denylist".to_string(),
        serde_json::Value::Array(
            result
                .iter()
                .map(|(_, _, value)| serde_json::Value::String(value.clone()))
                .collect(),
        ),
    );
    Ok(result)
}

fn apply_extended_config_patch(
    root: &Path,
    layer_id: &str,
    patch: ExtendedConfigPatch,
    expected_revision: &str,
    session: &str,
) -> Result<Response, String> {
    let id = Uuid::parse_str(layer_id).map_err(|_| STALE_SNAPSHOT.to_string())?;
    let capability = {
        let mut capabilities = layer_capabilities()
            .lock()
            .map_err(|_| poisoned("settings capability"))?;
        let capability = capabilities
            .get(&id)
            .cloned()
            .ok_or_else(|| STALE_SNAPSHOT.to_string())?;
        if capability.root != root
            || capability.session != session
            || capability.revision != expected_revision
        {
            return Err(STALE_SNAPSHOT.to_string());
        }
        // One apply consumes the complete snapshot group, so an unused sibling
        // capability never outlives the view the patch was authored against.
        capabilities.retain(|_, other| {
            !(other.root == capability.root && other.session == capability.session)
        });
        capability
    };
    if !patch.redacted_mutations.is_empty() {
        return Err(UNSUPPORTED_REDACTED_MUTATIONS.to_string());
    }
    let target = capability.target.clone();
    let (raw, existed) = read_optional_config(&target)?;
    let current_hash = content_hash(&raw);
    if current_hash != capability.raw_revision {
        return Err(
            "configuration changed before patch; reload its authoritative snapshot".to_string(),
        );
    }
    let mut document: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|error| format!("settings layer is not a valid JSON document: {error}"))?;
    let operations = patch.operations;
    let mut selected = HashSet::new();
    for operation in &operations {
        let path = operation.path();
        let Some(field) = path
            .first()
            .and_then(|key| ExtendedConfigField::from_json_key(key))
        else {
            return Err("settings mutation path is not owned by the typed schema".to_string());
        };
        if field == ExtendedConfigField::ImageGeneration {
            return Err("image generation settings require the dedicated daemon API".to_string());
        }
        if path == ["redact".to_string(), "denylist".to_string()] {
            return Err("redact.denylist requires its opaque occurrence API".to_string());
        }
        if !selected.insert(path.to_vec()) {
            return Err("a settings path may be selected exactly once".to_string());
        }
    }
    for operation in &operations {
        match operation {
            ExtendedConfigPathMutation::Set { path, value } => {
                set_object_path(&mut document, path, value.clone())?;
            }
            ExtendedConfigPathMutation::Unset { path } => {
                unset_object_path(&mut document, path)?;
            }
        }
    }
    let object = document
        .as_object_mut()
        .ok_or_else(|| "extended config root must be a JSON object".to_string())?;
    let denylist_values =
        apply_denylist_sequence(object, patch.denylist, &capability.denylist_ids)?;
    let patched = serde_json::to_vec_pretty(&document).map_err(|error| error.to_string())?;
    let merged =
        cockpit_config::extended::render_saved_extended_config_preserving_image_generation(
            &patched, &raw,
        )
        .map_err(|error| format!("invalid settings document: {error}"))?;
    let merged_document: serde_json::Value = serde_json::from_slice(&merged)
        .map_err(|error| format!("invalid settings document: {error}"))?;
    let typed_projection = serde_json::to_value(
        serde_json::from_slice::<ExtendedConfig>(&merged)
            .map_err(|error| format!("invalid settings document: {error}"))?,
    )
    .map_err(|error| error.to_string())?;
    for operation in &operations {
        match operation {
            ExtendedConfigPathMutation::Set { path, value } => {
                if value_at_object_path(&typed_projection, path) != Some(value) {
                    return Err(
                        "settings Set path is not represented exactly by the typed schema"
                            .to_string(),
                    );
                }
            }
            ExtendedConfigPathMutation::Unset { path } => {
                if value_at_object_path(&merged_document, path).is_some() {
                    return Err("settings Unset path remained authored after rendering".to_string());
                }
            }
        }
    }
    let desired_hash = content_hash(&merged);
    let result_revision = settings_revision(capability.kind, &target, &desired_hash);
    let config_generation = if desired_hash != current_hash || (patch.materialize && !existed) {
        cockpit_config::config::write_config_bytes_atomic(&target, &merged)
            .map_err(|error| format!("writing {}: {error}", target.display()))?;
        publish_config_generation()
    } else {
        current_config_generation()
    };
    Ok(Response::ExtendedConfigSaved {
        client_operation_id: String::new(),
        request_hash: String::new(),
        mutation_intent_hash: String::new(),
        hash: result_revision.clone(),
        config_generation,
        layer_id: layer_id.to_string(),
        layer: capability.kind,
        consumed_revision: expected_revision.to_string(),
        result_revision: result_revision.clone(),
        status: ConfigCommitStatus::Committed,
        publication: ConfigPublicationStatus::Published,
        denylist: denylist_values
            .iter()
            .enumerate()
            .map(
                |(index, (consumed, client_nonce, value))| CommittedDenylistEntry {
                    entry_id: denylist_occurrence_id(
                        capability.kind,
                        &target,
                        &result_revision,
                        index,
                        value,
                    ),
                    consumed_entry_id: client_nonce.is_none().then(|| consumed.clone()),
                    client_nonce: client_nonce.clone(),
                    display_mask: cockpit_proto::REDACTED_DENYLIST_MASK.to_string(),
                },
            )
            .collect(),
    })
}

// ── Provider catalog ────────────────────────────────────────────────────────

/// The owner projection of the layered provider catalog. Header values are
/// replaced by occurrence markers as the daemon does; the fake has no secret
/// store, so URLs and credential references keep their authored values instead
/// of being rewritten by the daemon's owner-view redaction.
fn provider_catalog_snapshot(
    root: &Path,
    provider_id: Option<&str>,
    snapshot_session_id: &str,
) -> Result<Response, String> {
    let mut paths = cockpit_config::dirs::config_file_paths_for_load(root);
    // A fixture target under this root is its most specific layer, so it merges
    // last and wins — the same precedence the settings snapshot gives it.
    let registered = extra_layer_targets()
        .lock()
        .map(|targets| targets.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    for target in registered {
        if target.starts_with(root) && !paths.contains(&target) {
            paths.push(target);
        }
    }
    let mut config = cockpit_config::providers::ConfigDoc::providers_from_paths(&paths);
    if let Some(provider_id) = provider_id {
        let entry = config
            .providers
            .remove(provider_id)
            .ok_or_else(|| format!("provider `{provider_id}` is not configured"))?;
        config.providers.clear();
        config.providers.insert(provider_id.to_string(), entry);
    }
    let providers = config
        .providers
        .iter()
        .map(|(id, entry)| {
            let headers = entry
                .headers
                .iter()
                .map(|header| cockpit_proto::ProviderHeaderView {
                    name: header.name.clone(),
                    value: "[redacted]".to_string(),
                    redacted: true,
                })
                .collect();
            let credential_configured = entry.credential_ref.is_some() || !entry.headers.is_empty();
            let mut projected = entry.clone();
            projected.headers.clear();
            (
                id.clone(),
                cockpit_proto::ProviderEntryView {
                    entry: projected,
                    headers,
                    credential_configured,
                },
            )
        })
        .collect();
    let mcp_path = mcp_target_path(root);
    let _mcp_lock = cockpit_config::config::hold_config_mutation_lock(&mcp_path)
        .map_err(|error| error.to_string())?;
    let mcp_raw_revision = mcp_revision(root);
    // Same owner-view redaction the daemon applies, through the shared
    // helper, so /mcp tests exercise the real sentinel round-trip.
    let mcp_config_json = {
        let mut config = cockpit_core::mcp::config::McpConfig::discover(root);
        cockpit_core::mcp::config::redact_config_for_owner_view(&mut config);
        serde_json::to_string(&config).ok()
    };
    let mcp_authored_config_json = {
        let mut config = std::fs::read_to_string(&mcp_path)
            .ok()
            .and_then(|raw| cockpit_core::mcp::config::McpConfig::parse(&raw).ok())
            .unwrap_or_default();
        cockpit_core::mcp::config::redact_config_for_owner_view(&mut config);
        serde_json::to_string(&config).ok()
    };
    Ok(Response::ProviderCatalogSnapshot {
        config: cockpit_proto::ProviderConfigView {
            providers,
            category_defaults: config.category_defaults.clone(),
            on_unlisted_models_fetch: config.on_unlisted_models_fetch,
            active_model: config.active_model.clone(),
            mcp_config_json,
            mcp_authored_config_json,
            mcp_owner_root: Some(root.display().to_string()),
            mcp_config_path: Some(mcp_path.display().to_string()),
            mcp_edit_capability: Some(mcp_edit_capability(root, &mcp_path, &mcp_raw_revision)),
            mcp_revision: Some(mcp_raw_revision.clone()),
            // No TUI surface reads the extended projection from this response;
            // settings loads it through its own layer snapshot instead.
            extended_config_json: None,
        },
        snapshot_session_id: snapshot_session_id.to_string(),
        layer_id: mint(b"mcp-layer/v1", &[root.as_os_str().as_encoded_bytes()]),
        owner_root: root.display().to_string(),
        base_revision: mcp_raw_revision,
        config_generation: current_config_generation(),
    })
}

fn mcp_revision(root: &Path) -> String {
    let value: serde_json::Value = std::fs::read_to_string(mcp_target_path(root))
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    serde_json::to_vec(&value)
        .map(|bytes| content_hash(&bytes))
        .unwrap_or_else(|_| content_hash(b"invalid-mcp-layer"))
}

fn mcp_target_path(root: &Path) -> PathBuf {
    cockpit_config::dirs::mcp_file_paths_for_load(root)
        .last()
        .cloned()
        .unwrap_or_else(|| root.join(".cockpit").join("mcp.json"))
}

fn mcp_edit_capability(root: &Path, path: &Path, revision: &str) -> String {
    mint(
        b"mcp-edit-capability/v1",
        &[
            root.as_os_str().as_encoded_bytes(),
            path.as_os_str().as_encoded_bytes(),
            revision.as_bytes(),
        ],
    )
}

fn merge_fake_mcp_server_field(
    target: &mut serde_json::Map<String, serde_json::Value>,
    key: String,
    value: serde_json::Value,
) {
    if key != "auth" {
        target.insert(key, value);
        return;
    }
    let replacement = value.as_object().cloned();
    let same_kind = target
        .get("auth")
        .and_then(serde_json::Value::as_object)
        .and_then(|auth| auth.get("kind"))
        == replacement.as_ref().and_then(|auth| auth.get("kind"));
    if !same_kind {
        target.insert(key, value);
        return;
    }
    let Some(replacement) = replacement else {
        target.insert(key, value);
        return;
    };
    let Some(existing) = target
        .get_mut("auth")
        .and_then(serde_json::Value::as_object_mut)
    else {
        target.insert(key, value);
        return;
    };
    for auth_key in [
        "kind",
        "header",
        "value",
        "credential_ref",
        "vars",
        "credential_refs",
        "authorize_url",
        "token_url",
        "client_id",
        "scopes",
    ] {
        if let Some(value) = replacement.get(auth_key) {
            existing.insert(auth_key.into(), value.clone());
        } else {
            existing.remove(auth_key);
        }
    }
}

/// Disk-backed `SaveMcpConfig`. It mirrors the daemon's authored-layer patch
/// shape and preserves unknown raw JSON, but intentionally has no vault.
///
/// Divergences from production: there is no secret vault, so staged-secret
/// mutations fail closed; ownership claims, journaling, and redaction-table
/// publication are unavailable.
fn save_mcp_config(
    client_operation_id: &str,
    root: &Path,
    snapshot_capability: &str,
    owner_root: &str,
    config_path: &str,
    expected_revision: &str,
    supplied_mutation_intent_hash: &str,
    patch_wire: &str,
    secret_values_json: &str,
    target_scope: None,
) -> Result<Response, String> {
    let path = mcp_target_path(root);
    let expected_path = path.display().to_string();
    let expected_owner = root.display().to_string();
    if owner_root != expected_owner
        || config_path != expected_path
        || snapshot_capability != mcp_edit_capability(root, &path, expected_revision)
    {
        return Err("MCP edit authority does not match the selected raw layer".into());
    }
    let mutation_intent_hash =
        serde_json::to_vec(&("save_mcp_config", root.display().to_string(), patch_wire))
            .map(|bytes| content_hash(&bytes))
            .map_err(|error| error.to_string())?;
    if mutation_intent_hash != supplied_mutation_intent_hash {
        return Err("MCP mutation intent does not match its typed patch".into());
    }
    cockpit_host::private_fs::ensure_parent_dir_private(&path)
        .map_err(|error| error.to_string())?;
    let _file_lock = cockpit_config::config::hold_config_mutation_lock(&path)
        .map_err(|error| error.to_string())?;
    let consumed_revision = mcp_revision(root);
    if consumed_revision != expected_revision {
        return Err("MCP target changed since the authority snapshot".into());
    }
    let secret_values: BTreeMap<String, cockpit_proto::SensitiveWirePayload> =
        serde_json::from_str(secret_values_json)
            .map_err(|error| format!("invalid MCP secret values: {error}"))?;
    if !secret_values.is_empty() {
        return Err("daemonless MCP fallback cannot persist staged secrets".into());
    }
    let mut raw: serde_json::Value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    let prior = cockpit_core::mcp::config::McpConfig::parse(
        &serde_json::to_string(&raw).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let effective = cockpit_core::mcp::config::McpConfig::discover(root);
    let servers = raw
        .as_object_mut()
        .ok_or("invalid authored MCP document")?
        .entry("servers")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or("invalid authored MCP servers")?;
    let patch: cockpit_proto::McpConfigPatch =
        serde_json::from_str(patch_wire).map_err(|error| error.to_string())?;
    let mut touched = BTreeSet::new();
    for operation in patch.operations {
        match operation {
            cockpit_proto::McpConfigPatchOperation::AddServer { name, server_json } => {
                if effective.servers.contains_key(&name) {
                    return Err(format!("MCP server `{name}` has the wrong layer ownership"));
                }
                touched.insert(name.clone());
                let server: serde_json::Value = serde_json::from_str(&server_json)
                    .map_err(|error| format!("invalid MCP server: {error}"))?;
                servers.insert(name, server);
            }
            cockpit_proto::McpConfigPatchOperation::MaterializeInheritedServer {
                name,
                server_json,
            } => {
                if prior.servers.contains_key(&name) || !effective.servers.contains_key(&name) {
                    return Err(format!("MCP server `{name}` has the wrong layer ownership"));
                }
                if cockpit_core::mcp::config::server_has_credential_material(
                    &effective.servers[&name],
                ) {
                    return Err(format!(
                        "daemonless MCP fallback cannot materialize credential-bearing server `{name}`"
                    ));
                }
                touched.insert(name.clone());
                let server: serde_json::Value = serde_json::from_str(&server_json)
                    .map_err(|error| format!("invalid MCP server: {error}"))?;
                servers.insert(name, server);
            }
            cockpit_proto::McpConfigPatchOperation::UpdateAuthoredServer {
                name,
                set_fields_json,
                unset_fields,
            } => {
                if !prior.servers.contains_key(&name) {
                    return Err(format!("MCP server `{name}` is not authored"));
                }
                touched.insert(name.clone());
                let object = servers
                    .get_mut(&name)
                    .and_then(serde_json::Value::as_object_mut)
                    .ok_or_else(|| format!("MCP server `{name}` is not authored"))?;
                let fields: serde_json::Map<String, serde_json::Value> =
                    serde_json::from_str(&set_fields_json).map_err(|error| error.to_string())?;
                for (key, value) in fields {
                    merge_fake_mcp_server_field(object, key, value);
                }
                for field in unset_fields {
                    object.remove(&field);
                }
            }
            cockpit_proto::McpConfigPatchOperation::DeleteAuthoredServer { name } => {
                if !prior.servers.contains_key(&name) {
                    return Err(format!("MCP server `{name}` is not authored"));
                }
                servers.remove(&name);
            }
        }
    }
    let encoded = serde_json::to_string(&raw).map_err(|error| error.to_string())?;
    let mut config = cockpit_core::mcp::config::McpConfig::parse(&encoded)
        .map_err(|error| format!("invalid patched MCP config: {error}"))?;
    cockpit_core::mcp::config::restore_owner_view_redactions(&mut config, &prior);
    for name in &touched {
        let server = config
            .servers
            .get(name)
            .ok_or_else(|| format!("MCP server `{name}` disappeared during validation"))?;
        if cockpit_core::mcp::config::server_has_credential_material(server) {
            return Err(format!(
                "daemonless MCP fallback cannot persist credential-bearing server `{name}`"
            ));
        }
    }
    let servers = raw
        .get_mut("servers")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("invalid authored MCP servers")?;
    for name in touched {
        if let Some(server) = config.servers.get(&name) {
            let normalized = serde_json::to_value(server).map_err(|error| error.to_string())?;
            let normalized = normalized
                .as_object()
                .ok_or("invalid normalized MCP server")?;
            let raw_server = servers
                .get_mut(&name)
                .and_then(serde_json::Value::as_object_mut)
                .ok_or("invalid raw MCP server")?;
            for (key, value) in normalized {
                merge_fake_mcp_server_field(raw_server, key.clone(), value.clone());
            }
        }
    }
    let body = serde_json::to_string_pretty(&raw).map_err(|error| error.to_string())?;
    if mcp_revision(root) != consumed_revision {
        return Err("MCP target changed before publication".into());
    }
    cockpit_host::private_fs::ensure_parent_dir_private(&path)
        .map_err(|error| error.to_string())?;
    cockpit_host::private_fs::write_private_file(&path, format!("{body}\n").as_bytes())
        .map_err(|error| format!("writing mcp.json: {error}"))?;
    let credential_count = 0;
    let config_generation = publish_config_generation();
    Ok(Response::McpConfigCommitted {
        client_operation_id: client_operation_id.to_string(),
        request_hash: content_hash(patch_wire.as_bytes()),
        mutation_intent_hash,
        project_root: root.display().to_string(),
        owner_root: root.display().to_string(),
        config_path: path.display().to_string(),
        consumed_revision,
        result_revision: mcp_revision(root),
        config_generation,
        credential_count: u32::try_from(credential_count).unwrap_or(u32::MAX),
    })
}

// ── Agents ──────────────────────────────────────────────────────────────────

fn validate_agent_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > cockpit_proto::MAX_AGENT_NAME_BYTES
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err("agent name is invalid".to_string());
    }
    Ok(())
}

/// The one workspace-owned edit target for an agent.
fn project_agent_path(root: &Path, name: &str) -> Result<PathBuf, String> {
    validate_agent_name(name)?;
    Ok(root.join(".cockpit/agents").join(format!("{name}.md")))
}

fn read_optional_agent(path: &Path) -> Result<Option<Vec<u8>>, String> {
    cockpit_config::config::read_config_file_nofollow(path)
        .map_err(|error| format!("reading {}: {error}", path.display()))
}

/// Flat definitions are owned by their exact parent directory, so an effective
/// source outside the workspace target is never silently shadowed.
fn classify_source_layer(root: &Path, source: &Path, target: &Path) -> AgentSourceLayer {
    if source == target {
        return AgentSourceLayer::Workspace;
    }
    let Some(owner) = source.parent() else {
        return AgentSourceLayer::OtherConfigLayer;
    };
    let ordinary = cockpit_config::dirs::discover_config_dirs(root)
        .into_iter()
        .map(|directory| directory.path.join("agents"))
        .collect::<HashSet<_>>();
    if ordinary.contains(owner) {
        AgentSourceLayer::OtherConfigLayer
    } else if cockpit_core::agents::agent_search_dirs(root)
        .into_iter()
        .any(|directory| directory == owner)
    {
        AgentSourceLayer::ConfiguredDirectory
    } else {
        AgentSourceLayer::OtherConfigLayer
    }
}

/// `(source layer, opaque source identity, exact authored markdown, whether the
/// workspace target exists)` for the effective definition of `name`.
fn source_snapshot_parts(
    root: &Path,
    name: &str,
) -> Result<(AgentSourceLayer, String, String, bool), String> {
    let project_override = project_agent_path(root, name)?;
    let target_exists = read_optional_agent(&project_override)?.is_some();
    match cockpit_core::agents::find_override(root, name) {
        Some(source) => {
            let metadata = std::fs::symlink_metadata(&source)
                .map_err(|error| format!("agent management failed: {error}"))?;
            if metadata.file_type().is_dir() {
                return Err(READ_ONLY_DIRECTORY_AGENT.to_string());
            }
            let raw = read_optional_agent(&source)?.ok_or_else(|| {
                "agent source changed while the snapshot was being acquired".to_string()
            })?;
            if raw.len() > cockpit_proto::MAX_AGENT_MARKDOWN_BYTES {
                return Err(format!(
                    "agent definition exceeds the {}-byte local editor limit",
                    cockpit_proto::MAX_AGENT_MARKDOWN_BYTES
                ));
            }
            let markdown = String::from_utf8(raw)
                .map_err(|_| "agent definition is not valid UTF-8".to_string())?;
            let layer = classify_source_layer(root, &source, &project_override);
            let identity = opaque_source_identity(root, &source, layer, markdown.as_bytes())?;
            Ok((layer, identity, markdown, target_exists))
        }
        None => {
            let markdown = cockpit_core::agents::resolve(root, name)
                .map_err(|error| format!("invalid agent definition: {error}"))?
                .ok_or_else(|| format!("agent `{name}` was not found"))?
                .to_markdown()
                .map_err(|error| format!("invalid agent definition: {error}"))?;
            if markdown.len() > cockpit_proto::MAX_AGENT_MARKDOWN_BYTES {
                return Err(format!(
                    "embedded agent definition exceeds the {}-byte local editor limit",
                    cockpit_proto::MAX_AGENT_MARKDOWN_BYTES
                ));
            }
            let identity = embedded_source_identity(root, name, markdown.as_bytes());
            Ok((
                AgentSourceLayer::Embedded,
                identity,
                markdown,
                target_exists,
            ))
        }
    }
}

fn finalized_snapshot(mut snapshot: AgentEditSnapshot) -> AgentEditSnapshot {
    snapshot.projection_digest = cockpit_proto::agent_edit_projection_material(&snapshot);
    snapshot
}

fn agent_edit_snapshot(root: &Path, name: &str) -> Result<AgentEditSnapshot, String> {
    validate_agent_name(name)?;
    let def = cockpit_core::agents::resolve(root, name)
        .map_err(|error| format!("invalid agent definition: {error}"))?
        .ok_or_else(|| format!("agent `{name}` was not found"))?;
    let canonical_preview = def
        .to_markdown()
        .map_err(|error| format!("invalid agent definition: {error}"))?;
    if canonical_preview.len() > cockpit_proto::MAX_AGENT_MARKDOWN_BYTES {
        return Err(format!(
            "canonical agent preview exceeds the {}-byte local editor limit",
            cockpit_proto::MAX_AGENT_MARKDOWN_BYTES
        ));
    }
    let (source_layer, source_identity, markdown, target_exists) =
        source_snapshot_parts(root, name)?;
    let revision = definition_revision(
        name,
        source_layer,
        &source_identity,
        &cockpit_core::assistants::markdown_content_hash(&markdown),
        target_exists,
    );
    let goal_supervision_json = (!def.goal_supervision.is_empty())
        .then(|| {
            serde_json::to_string(&def.goal_supervision)
                .map_err(|error| format!("invalid agent definition: {error}"))
        })
        .transpose()?;
    if goal_supervision_json
        .as_ref()
        .is_some_and(|value| value.len() > cockpit_proto::MAX_AGENT_METADATA_BYTES)
    {
        return Err("agent goal supervision projection is too large".to_string());
    }
    Ok(finalized_snapshot(AgentEditSnapshot {
        name: name.to_string(),
        kind: if cockpit_core::agents::is_builtin_agent(name) {
            AgentEntryKind::Builtin
        } else {
            AgentEntryKind::Custom
        },
        overridden: source_layer != AgentSourceLayer::Embedded,
        markdown,
        canonical_preview,
        source_layer,
        source_identity,
        edit_target: AgentEditTarget::Workspace,
        revision,
        goal_supervision_json,
        editable: source_layer == AgentSourceLayer::Workspace,
        supports_goal_supervision: def.vnext.is_none(),
        projection_digest: String::new(),
    }))
}

fn inventory_entries(root: &Path) -> Result<Vec<AgentInventoryEntry>, String> {
    let listings = cockpit_core::agents::list_all(root);
    if listings.len() > cockpit_proto::MAX_AGENT_INVENTORY_ENTRIES {
        return Err(format!(
            "agent inventory exceeds the {}-entry local response limit; remove unused definitions",
            cockpit_proto::MAX_AGENT_INVENTORY_ENTRIES
        ));
    }
    let mut entries = Vec::with_capacity(listings.len());
    for listing in listings {
        // A directory-form override is unopenable in the editor but must still
        // appear in the inventory with a stable identity.
        let source = match source_snapshot_parts(root, &listing.name) {
            Ok(parts) => Ok(parts),
            Err(error) => match cockpit_core::agents::find_override(root, &listing.name) {
                Some(path) => {
                    let metadata = std::fs::symlink_metadata(&path)
                        .map_err(|error| format!("agent management failed: {error}"))?;
                    if metadata.file_type().is_symlink() || !metadata.is_dir() {
                        Err(error)
                    } else {
                        let target = project_agent_path(root, &listing.name)?;
                        let layer = classify_source_layer(root, &path, &target);
                        let identity = opaque_source_identity(root, &path, layer, b"")?;
                        Ok((
                            layer,
                            identity,
                            String::new(),
                            read_optional_agent(&target)?.is_some(),
                        ))
                    }
                }
                None => Err(error),
            },
        };
        let kind = listing.kind;
        let name = listing.name;
        let (description, model, valid, diagnostic) = match listing.def {
            Ok(def) => (Some(def.description), def.model, true, None),
            Err(_) => (
                None,
                None,
                false,
                Some(INVALID_AGENT_DIAGNOSTIC.to_string()),
            ),
        };
        if [
            description.as_deref(),
            model.as_deref(),
            diagnostic.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|value| value.len() > cockpit_proto::MAX_AGENT_METADATA_BYTES)
        {
            return Err(format!(
                "agent `{name}` metadata exceeds the safe local response bounds"
            ));
        }
        let (source_layer, source_identity, markdown, target_exists) = source?;
        let revision = definition_revision(
            &name,
            source_layer,
            &source_identity,
            &cockpit_core::assistants::markdown_content_hash(&markdown),
            target_exists,
        );
        let mut entry = AgentInventoryEntry {
            name,
            kind: match kind {
                AgentKind::Builtin { .. } => AgentEntryKind::Builtin,
                AgentKind::Custom => AgentEntryKind::Custom,
            },
            overridden: matches!(kind, AgentKind::Builtin { overridden: true }),
            description,
            model,
            valid,
            diagnostic,
            source_layer,
            source_identity,
            revision,
            editable: source_layer == AgentSourceLayer::Workspace && !markdown.is_empty(),
            projection_digest: String::new(),
        };
        entry.projection_digest = cockpit_proto::agent_inventory_entry_projection_material(&entry);
        entries.push(entry);
    }
    Ok(entries)
}

fn agent_inventory(root: &Path) -> Result<Response, String> {
    let entries = inventory_entries(root)?;
    let inventory_revision = inventory_revision(&entries);
    Ok(Response::AgentInventory {
        entries,
        inventory_revision,
        project_root: root.to_string_lossy().into_owned(),
        requested_project_root: root.to_string_lossy().into_owned(),
        config_generation: current_config_generation(),
    })
}

fn ensure_revision(current: &str, expected: Option<&str>) -> Result<(), String> {
    match expected {
        Some(expected) if expected == current => Ok(()),
        Some(_) => Err("agent changed since the snapshot was read".to_string()),
        None => Err("agent mutation requires an expected revision".to_string()),
    }
}

fn write_agent_definition(target: &Path, markdown: &str) -> Result<(), String> {
    let parent = target
        .parent()
        .ok_or_else(|| "agent path has no parent".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("creating {}: {error}", parent.display()))?;
    cockpit_config::config::write_config_bytes_atomic(target, markdown.as_bytes())
        .map_err(|error| format!("writing {}: {error}", target.display()))
}

fn remove_agent_definition(target: &Path) -> Result<(), String> {
    cockpit_config::config::remove_config_file_atomic(target)
        .map_err(|error| format!("removing {}: {error}", target.display()))
}

/// A workspace definition is accepted only when it both parses and satisfies
/// the same invariants the daemon enforces before publishing it.
fn validate_workspace_definition(markdown: &str, name: &str, source: &str) -> Result<(), String> {
    let parsed = cockpit_core::agents::parse_agent(markdown, name, PathBuf::from(source))
        .map_err(|error| format!("invalid agent definition: {error}"))?;
    cockpit_core::agents::validate_invariants(&parsed)
        .map_err(|error| format!("invalid agent definition: {error}"))
}

fn reset_all_builtins(root: &Path) -> Result<u32, String> {
    let mut affected = 0;
    for name in BUILTIN_AGENT_NAMES {
        let target = project_agent_path(root, name)?;
        if read_optional_agent(&target)?.is_some() {
            remove_agent_definition(&target)?;
            affected += 1;
        }
    }
    Ok(affected)
}

fn mutate_agent(
    client_operation_id: String,
    mutation_intent_hash: String,
    root: &Path,
    mutation: AgentMutation,
    expected_revision: Option<String>,
) -> Result<AgentMutationResult, String> {
    let agent_name = cockpit_proto::agent_mutation_name(&mutation).map(str::to_owned);
    let consumed_revision = expected_revision.clone();
    let generation_before = current_config_generation();
    let resets_inventory = matches!(&mutation, AgentMutation::ResetAllBuiltins);
    let agent_name = cockpit_proto::agent_mutation_name(&mutation).map(String::from);
    let (changed, affected, snapshot) = match mutation {
        AgentMutation::EjectBuiltin { name } => {
            validate_agent_name(&name)?;
            if !cockpit_core::agents::is_builtin_agent(&name) {
                return Err("only a built-in agent can be ejected".to_string());
            }
            let before = agent_edit_snapshot(root, &name)?;
            ensure_revision(&before.revision, expected_revision.as_deref())?;
            if !matches!(
                before.source_layer,
                AgentSourceLayer::Workspace | AgentSourceLayer::Embedded
            ) {
                return Err(
                    "eject refused: another configuration layer already owns this override"
                        .to_string(),
                );
            }
            let target = project_agent_path(root, &name)?;
            if read_optional_agent(&target)?.is_some() {
                (false, 0, Some(agent_edit_snapshot(root, &name)?))
            } else {
                write_agent_definition(&target, &before.markdown)?;
                (true, 1, Some(agent_edit_snapshot(root, &name)?))
            }
        }
        AgentMutation::SaveDefinition { name, markdown } => {
            validate_agent_name(&name)?;
            let current = agent_edit_snapshot(root, &name)?;
            ensure_revision(&current.revision, expected_revision.as_deref())?;
            if !matches!(
                current.source_layer,
                AgentSourceLayer::Workspace | AgentSourceLayer::Embedded
            ) {
                return Err("save refused: another configuration layer owns this agent".to_string());
            }
            validate_workspace_definition(&markdown, &name, "<daemon-agent-edit>")?;
            let target = project_agent_path(root, &name)?;
            if read_optional_agent(&target)?.as_deref() == Some(markdown.as_bytes()) {
                (false, 0, Some(current))
            } else {
                write_agent_definition(&target, &markdown)?;
                (true, 1, Some(agent_edit_snapshot(root, &name)?))
            }
        }
        AgentMutation::CreateDefinition { name, markdown } => {
            validate_agent_name(&name)?;
            if cockpit_core::agents::resolve(root, &name)
                .map_err(|error| format!("invalid agent definition: {error}"))?
                .is_some()
            {
                return Err("agent name already resolves in a configuration layer".to_string());
            }
            let target = project_agent_path(root, &name)?;
            if read_optional_agent(&target)?.is_some() {
                return Err("workspace agent already exists".to_string());
            }
            if expected_revision.is_some() {
                return Err(
                    "create uses the daemon's authoritative absence check, not a document revision"
                        .to_string(),
                );
            }
            validate_workspace_definition(&markdown, &name, "<daemon-agent-create>")?;
            write_agent_definition(&target, &markdown)?;
            (true, 1, Some(agent_edit_snapshot(root, &name)?))
        }
        AgentMutation::DeleteCustom { name } => {
            validate_agent_name(&name)?;
            if cockpit_core::agents::is_builtin_agent(&name) {
                return Err("built-in agents cannot be deleted".to_string());
            }
            let current = agent_edit_snapshot(root, &name)?;
            ensure_revision(&current.revision, expected_revision.as_deref())?;
            if current.source_layer != AgentSourceLayer::Workspace {
                return Err("custom agent is not owned by the workspace layer".to_string());
            }
            let target = project_agent_path(root, &name)?;
            if !target.is_file() {
                return Err("custom agent is not owned by this workspace layer".to_string());
            }
            remove_agent_definition(&target)?;
            (true, 1, None)
        }
        AgentMutation::ResetBuiltin { name } => {
            validate_agent_name(&name)?;
            if !cockpit_core::agents::is_builtin_agent(&name) {
                return Err("only a built-in agent can be reset".to_string());
            }
            let current = agent_edit_snapshot(root, &name)?;
            ensure_revision(&current.revision, expected_revision.as_deref())?;
            if current.source_layer != AgentSourceLayer::Workspace {
                return Err("built-in override is not owned by the workspace layer".to_string());
            }
            let target = project_agent_path(root, &name)?;
            if target.is_file() {
                remove_agent_definition(&target)?;
                (true, 1, Some(agent_edit_snapshot(root, &name)?))
            } else {
                (false, 0, Some(current))
            }
        }
        AgentMutation::ResetAllBuiltins => {
            let current = inventory_revision(&inventory_entries(root)?);
            ensure_revision(&current, expected_revision.as_deref())?;
            let affected = reset_all_builtins(root)?;
            (affected != 0, affected, None)
        }
        AgentMutation::SaveGoalSupervision { name, patch } => {
            validate_agent_name(&name)?;
            let current = agent_edit_snapshot(root, &name)?;
            ensure_revision(&current.revision, expected_revision.as_deref())?;
            if !matches!(
                current.source_layer,
                AgentSourceLayer::Workspace | AgentSourceLayer::Embedded
            ) {
                return Err(
                    "goal settings cannot shadow an agent owned by another configuration layer"
                        .to_string(),
                );
            }
            let mut def = cockpit_core::agents::parse_agent(
                &current.markdown,
                &name,
                PathBuf::from("<daemon-agent-goal-settings>"),
            )
            .map_err(|error| format!("invalid agent definition: {error}"))?;
            if def.vnext.is_some() {
                return Err(
                    "agent-scoped goal settings are unavailable for vNext agents".to_string(),
                );
            }
            // `None` leaves a field untouched; `Some(None)` clears it back to
            // the inherited value.
            if let Some(value) = patch.cold_skeptic_count {
                def.goal_supervision.cold_skeptic_count = value;
            }
            if let Some(value) = patch.cold_skeptic_model {
                def.goal_supervision.cold_skeptic_model = value;
            }
            if let Some(value) = patch.max_verification_attempts {
                def.goal_supervision.max_verification_attempts = value;
            }
            def.goal_supervision
                .validate()
                .map_err(|error| format!("invalid agent definition: {error}"))?;
            cockpit_core::agents::validate_invariants(&def)
                .map_err(|error| format!("invalid agent definition: {error}"))?;
            let markdown = def
                .to_markdown()
                .map_err(|error| format!("invalid agent definition: {error}"))?;
            let target = project_agent_path(root, &name)?;
            if markdown == current.markdown {
                (false, 0, Some(current))
            } else {
                write_agent_definition(&target, &markdown)?;
                (true, 1, Some(agent_edit_snapshot(root, &name)?))
            }
        }
    };
    let config_generation = if changed {
        publish_config_generation()
    } else {
        generation_before
    };
    let result_inventory_revision = resets_inventory
        .then(|| inventory_entries(root).map(|entries| inventory_revision(&entries)))
        .transpose()?;
    let result_revision = snapshot
        .as_ref()
        .map(|snapshot| snapshot.revision.clone())
        .or_else(|| result_inventory_revision.clone())
        .unwrap_or_else(|| {
            content_hash(
                format!(
                    "agent-mutation-tombstone:{}:{}:{}",
                    root.display(),
                    agent_name.as_deref().unwrap_or("inventory"),
                    config_generation
                )
                .as_bytes(),
            )
        });
    Ok(AgentMutationResult {
        client_operation_id,
        mutation_intent_hash,
        project_root: root.to_string_lossy().into_owned(),
        requested_project_root: root.to_string_lossy().into_owned(),
        owner_scope: format!("project:{}", root.to_string_lossy()),
        agent_name,
        changed,
        affected,
        snapshot,
        consumed_config_generation: generation_before,
        result_config_generation: config_generation,
        config_generation,
        inventory_revision: result_inventory_revision,
        consumed_revision,
        result_revision,
        completed_lease_id: None,
        outcome: AgentMutationOutcome::Reconciled,
    })
}

fn begin_editor_lease(
    client_operation_id: String,
    root: &Path,
    name: &str,
    expected_revision: String,
) -> Result<Response, String> {
    let snapshot = agent_edit_snapshot(root, name)?;
    ensure_revision(&snapshot.revision, Some(&expected_revision))?;
    let lease_id = Uuid::new_v4().to_string();
    editor_leases()
        .lock()
        .map_err(|_| poisoned("agent editor lease"))?
        .insert(
            lease_id.clone(),
            EditorLease {
                root: root.to_path_buf(),
                name: name.to_string(),
                revision: expected_revision,
            },
        );
    Ok(Response::AgentEditorLeaseBegun(AgentEditorLease {
        client_operation_id,
        lease_id,
        expires_at_unix_ms: chrono::Utc::now().timestamp_millis() + EDITOR_LEASE_TTL_MS,
        snapshot,
    }))
}

fn complete_editor_lease(
    client_operation_id: String,
    root: &Path,
    lease_id: &str,
    markdown: Option<cockpit_proto::SensitiveWirePayload>,
) -> Result<Response, String> {
    let lease = editor_leases()
        .lock()
        .map_err(|_| poisoned("agent editor lease"))?
        .get(lease_id)
        .cloned()
        .ok_or_else(|| "editor lease is absent, expired, or already completed".to_string())?;
    if lease.root != root {
        return Err("editor lease belongs to another workspace".to_string());
    }
    // The lease stays reserved until completion reaches a terminal state, so a
    // failed save leaves the same retryable token in place.
    let is_save = markdown.is_some();
    let mut result = match markdown {
        Some(markdown) => {
            let mut markdown = markdown.into_zeroizing();
            mutate_agent(
                client_operation_id.clone(),
                content_hash(format!("editor-save:{lease_id}:{}", lease.name).as_bytes()),
                root,
                AgentMutation::SaveDefinition {
                    name: lease.name.clone(),
                    markdown: std::mem::take(&mut *markdown),
                },
                Some(lease.revision.clone()),
            )?
        }
        None => {
            let generation = current_config_generation();
            AgentMutationResult {
                client_operation_id: client_operation_id.clone(),
                mutation_intent_hash: content_hash(format!("editor-cancel:{lease_id}").as_bytes()),
                project_root: root.to_string_lossy().into_owned(),
                requested_project_root: root.to_string_lossy().into_owned(),
                owner_scope: format!("project:{}", root.to_string_lossy()),
                agent_name: Some(lease.name.clone()),
                changed: false,
                affected: 0,
                snapshot: None,
                consumed_config_generation: generation,
                result_config_generation: generation,
                config_generation: generation,
                inventory_revision: None,
                consumed_revision: Some(lease.revision.clone()),
                result_revision: lease.revision.clone(),
                completed_lease_id: None,
                outcome: AgentMutationOutcome::Reconciled,
            }
        }
    };
    result.completed_lease_id = Some(lease_id.to_string());
    let consumed_config_generation = result.consumed_config_generation;
    let result_config_generation = result.result_config_generation;
    let status = if is_save {
        AgentEditorSettlementStatus::Saved {
            result_revision: result.result_revision.clone(),
            outcome: result.outcome.clone(),
        }
    } else {
        AgentEditorSettlementStatus::Cancelled
    };
    editor_leases()
        .lock()
        .map_err(|_| poisoned("agent editor lease"))?
        .remove(lease_id);
    Ok(Response::AgentEditorLeaseCompleted(AgentEditorCompletion {
        client_operation_id,
        project_root: root.to_string_lossy().into_owned(),
        owner_scope: format!("project:{}", root.to_string_lossy()),
        agent_name: lease.name,
        lease_id: lease_id.to_string(),
        consumed_revision: lease.revision,
        consumed_config_generation: Some(consumed_config_generation),
        result_config_generation: Some(result_config_generation),
        status,
    }))
}
