//! Daemon-owned agent discovery and mutation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::daemon::proto::{
    AgentEditSnapshot, AgentEditTarget, AgentEditorLease, AgentEntryKind, AgentInventoryEntry,
    AgentMutation, AgentMutationResult, AgentSourceLayer, ErrorCode, ErrorPayload, Response,
};
use crate::daemon::server::DaemonContext;

#[derive(Clone)]
struct EditorLeaseState {
    principal_digest: String,
    root: PathBuf,
    name: String,
    revision: String,
    expires_at: Instant,
}

const EDITOR_LEASE_TTL: Duration = Duration::from_secs(8 * 60 * 60);
const MAX_EDITOR_LEASES: usize = 64;

fn editor_leases() -> &'static Mutex<HashMap<Uuid, EditorLeaseState>> {
    static LEASES: OnceLock<Mutex<HashMap<Uuid, EditorLeaseState>>> = OnceLock::new();
    LEASES.get_or_init(|| Mutex::new(HashMap::new()))
}

pub async fn inventory(
    ctx: &DaemonContext,
    project_root: String,
) -> Result<Response, ErrorPayload> {
    let root = trusted_root(ctx, &project_root).await?;
    tokio::task::spawn_blocking(move || {
        let _guard =
            cockpit_config::config::hold_config_mutation_lock(&root.join(".cockpit/config.json"))
                .map_err(internal)?;
        inventory_sync(&root)
    })
    .await
    .map_err(join_error)?
}

pub async fn edit_snapshot(
    ctx: &DaemonContext,
    project_root: String,
    name: String,
) -> Result<Response, ErrorPayload> {
    let root = trusted_root(ctx, &project_root).await?;
    tokio::task::spawn_blocking(move || {
        let _guard =
            cockpit_config::config::hold_config_mutation_lock(&root.join(".cockpit/config.json"))
                .map_err(internal)?;
        recover_reset_all(&root)?;
        snapshot_sync(&root, &name).map(Response::AgentEditSnapshot)
    })
    .await
    .map_err(join_error)?
}

pub async fn mutate(
    ctx: &DaemonContext,
    project_root: String,
    mutation: AgentMutation,
    expected_revision: Option<String>,
) -> Result<Response, ErrorPayload> {
    let root = trusted_root(ctx, &project_root).await?;
    tokio::task::spawn_blocking(move || mutate_sync(&root, mutation, expected_revision))
        .await
        .map_err(join_error)?
}

pub async fn begin_editor_lease(
    ctx: &DaemonContext,
    project_root: String,
    name: String,
    expected_revision: String,
    principal_digest: String,
) -> Result<Response, ErrorPayload> {
    let root = trusted_root(ctx, &project_root).await?;
    let snapshot = tokio::task::spawn_blocking({
        let root = root.clone();
        let name = name.clone();
        move || {
            let _guard = cockpit_config::config::hold_config_mutation_lock(
                &root.join(".cockpit/config.json"),
            )
            .map_err(internal)?;
            recover_reset_all(&root)?;
            snapshot_sync(&root, &name)
        }
    })
    .await
    .map_err(join_error)??;
    ensure_revision(&snapshot.revision, Some(&expected_revision))?;
    let lease_id = Uuid::new_v4();
    let mut leases = editor_leases().lock().map_err(lock_poison)?;
    let now = Instant::now();
    leases.retain(|_, lease| lease.expires_at > now);
    if leases.len() >= MAX_EDITOR_LEASES {
        return Err(conflict("too many active agent editor leases"));
    }
    leases.insert(
        lease_id,
        EditorLeaseState {
            principal_digest,
            root,
            name,
            revision: expected_revision,
            expires_at: now + EDITOR_LEASE_TTL,
        },
    );
    drop(leases);
    Ok(Response::AgentEditorLeaseBegun(AgentEditorLease {
        lease_id: lease_id.to_string(),
        expires_at_unix_ms: chrono::Utc::now().timestamp_millis()
            + i64::try_from(EDITOR_LEASE_TTL.as_millis()).unwrap_or(i64::MAX),
        snapshot,
    }))
}

pub async fn complete_editor_lease(
    ctx: &DaemonContext,
    project_root: String,
    lease_id: String,
    markdown: Option<String>,
    principal_digest: String,
) -> Result<Response, ErrorPayload> {
    let root = trusted_root(ctx, &project_root).await?;
    let id = Uuid::parse_str(&lease_id).map_err(|_| bad_request("invalid editor lease"))?;
    let lease = {
        let mut leases = editor_leases().lock().map_err(lock_poison)?;
        let now = Instant::now();
        leases.retain(|_, lease| lease.expires_at > now);
        leases
            .get(&id)
            .cloned()
            .ok_or_else(|| conflict("editor lease is absent, expired, or already completed"))?
    };
    if lease.root != root {
        return Err(bad_request("editor lease belongs to another workspace"));
    }
    if lease.principal_digest != principal_digest {
        return Err(ErrorPayload {
            code: ErrorCode::PermissionDenied,
            message: "agent editor lease belongs to another client principal".into(),
        });
    }
    let result = match markdown {
        Some(markdown) => tokio::task::spawn_blocking(move || {
            mutate_sync(
                &root,
                AgentMutation::SaveDefinition {
                    name: lease.name,
                    markdown,
                },
                Some(lease.revision),
            )
        })
        .await
        .map_err(join_error)??,
        None => Response::AgentMutated(AgentMutationResult {
            changed: false,
            affected: 0,
            snapshot: None,
            config_generation: crate::daemon::server::inventory::current_config_generation(),
        }),
    };
    let Response::AgentMutated(result) = result else {
        unreachable!("agent mutation always returns AgentMutated")
    };
    // A validation/CAS/write error returns above and deliberately retains the
    // lease for retry. Success and explicit cancellation consume it.
    editor_leases().lock().map_err(lock_poison)?.remove(&id);
    Ok(Response::AgentEditorLeaseCompleted(result))
}

async fn trusted_root(ctx: &DaemonContext, root: &str) -> Result<PathBuf, ErrorPayload> {
    let root = crate::daemon::fs_api::canonical_project_root(root)?;
    let policy = crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &root)
        .await
        .map_err(|error| ErrorPayload {
            code: ErrorCode::PermissionDenied,
            message: format!("workspace trust is required for agent management: {error:#}"),
        })?;
    if policy.mode != crate::db::workspace_trust::WorkspaceTrustMode::Trust {
        return Err(ErrorPayload {
            code: ErrorCode::PermissionDenied,
            message: "agent management requires a trusted workspace".into(),
        });
    }
    Ok(root)
}

fn inventory_sync(root: &Path) -> Result<Response, ErrorPayload> {
    recover_reset_all(root)?;
    let entries = crate::agents::list_all(root)
        .into_iter()
        .map(|entry| {
            let (description, model, valid, diagnostic) = match entry.def {
                Ok(def) => (Some(def.description), def.model, true, None),
                Err(error) => (None, None, false, Some(format!("{error:#}"))),
            };
            AgentInventoryEntry {
                name: entry.name,
                kind: match entry.kind {
                    crate::agents::AgentKind::Builtin { .. } => AgentEntryKind::Builtin,
                    crate::agents::AgentKind::Custom => AgentEntryKind::Custom,
                },
                overridden: matches!(
                    entry.kind,
                    crate::agents::AgentKind::Builtin { overridden: true }
                ),
                description,
                model,
                valid,
                diagnostic,
            }
        })
        .collect();
    let inventory_revision = inventory_revision(root)?;
    Ok(Response::AgentInventory {
        entries,
        inventory_revision,
        config_generation: crate::daemon::server::inventory::current_config_generation(),
    })
}

fn snapshot_sync(root: &Path, name: &str) -> Result<AgentEditSnapshot, ErrorPayload> {
    validate_name(name)?;
    let def = crate::agents::resolve(root, name)
        .map_err(bad_config)?
        .ok_or_else(|| bad_request(format!("agent `{name}` was not found")))?;
    let canonical_preview = def.to_markdown().map_err(bad_config)?;
    let project_override = project_agent_path(root, name)?;
    let target_exists = nofollow_read(&project_override)?.is_some();
    let (source_layer, source_identity, markdown) = match crate::agents::find_override(root, name) {
        Some(source) => {
            if source.is_dir() {
                return Err(bad_request(
                    "directory-form agents are read-only in the settings editor",
                ));
            }
            let raw = nofollow_read(&source)?.ok_or_else(|| {
                conflict("agent source changed while the snapshot was being acquired")
            })?;
            let markdown = String::from_utf8(raw)
                .map_err(|_| bad_request("agent definition is not valid UTF-8"))?;
            let layer = classify_source_layer(root, &source, &project_override);
            let identity = opaque_source_identity(root, &source, layer);
            (layer, identity, markdown)
        }
        None => (
            AgentSourceLayer::Embedded,
            format!("embedded:{name}"),
            canonical_preview.clone(),
        ),
    };
    let overridden = source_layer != AgentSourceLayer::Embedded;
    let revision = revision_for(
        name,
        source_layer,
        &source_identity,
        &markdown,
        target_exists,
    );
    let goal_supervision_json = (!def.goal_supervision.is_empty())
        .then(|| serde_json::to_string(&def.goal_supervision).map_err(bad_config))
        .transpose()?;
    Ok(AgentEditSnapshot {
        name: name.to_string(),
        kind: if crate::agents::is_builtin_agent(name) {
            AgentEntryKind::Builtin
        } else {
            AgentEntryKind::Custom
        },
        overridden,
        markdown,
        canonical_preview,
        source_layer,
        source_identity,
        edit_target: AgentEditTarget::Workspace,
        revision,
        goal_supervision_json,
        editable: source_layer == AgentSourceLayer::Workspace,
        supports_goal_supervision: def.vnext.is_none(),
    })
}

fn mutate_sync(
    root: &Path,
    mutation: AgentMutation,
    expected_revision: Option<String>,
) -> Result<Response, ErrorPayload> {
    let lock_target = root.join(".cockpit/config.json");
    let _guard =
        cockpit_config::config::hold_config_mutation_lock(&lock_target).map_err(internal)?;
    recover_reset_all(root)?;
    let generation_before = crate::daemon::server::inventory::current_config_generation();
    let (changed, affected, snapshot) = match mutation {
        AgentMutation::EjectBuiltin { name } => {
            validate_name(&name)?;
            if !crate::agents::is_builtin_agent(&name) {
                return Err(bad_request("only a built-in agent can be ejected"));
            }
            let before = snapshot_sync(root, &name)?;
            ensure_revision(&before.revision, expected_revision.as_deref())?;
            ensure_workspace_source_or_embedded(&before)?;
            let target = project_agent_path(root, &name)?;
            if nofollow_read(&target)?.is_some() {
                (false, 0, Some(snapshot_sync(root, &name)?))
            } else {
                let parent = target.parent().expect("agent path has parent");
                std::fs::create_dir_all(parent).map_err(internal)?;
                cockpit_config::config::write_config_bytes_atomic(
                    &target,
                    before.markdown.as_bytes(),
                )
                .map_err(internal)?;
                (true, 1, Some(snapshot_sync(root, &name)?))
            }
        }
        AgentMutation::SaveDefinition { name, markdown } => {
            validate_name(&name)?;
            let current = snapshot_sync(root, &name)?;
            ensure_revision(&current.revision, expected_revision.as_deref())?;
            if !matches!(
                current.source_layer,
                AgentSourceLayer::Workspace | AgentSourceLayer::Embedded
            ) {
                return Err(conflict(
                    "save refused: another configuration layer owns this agent",
                ));
            }
            let parsed =
                crate::agents::parse_agent(&markdown, &name, PathBuf::from("<daemon-agent-edit>"))
                    .map_err(bad_config)?;
            crate::agents::validate_invariants(&parsed).map_err(bad_config)?;
            let target = project_agent_path(root, &name)?;
            std::fs::create_dir_all(target.parent().expect("agent path has parent"))
                .map_err(internal)?;
            let old = nofollow_read(&target)?;
            if old.as_deref() == Some(markdown.as_bytes()) {
                (false, 0, Some(current))
            } else {
                cockpit_config::config::write_config_bytes_atomic(&target, markdown.as_bytes())
                    .map_err(internal)?;
                (true, 1, Some(snapshot_sync(root, &name)?))
            }
        }
        AgentMutation::CreateDefinition { name, markdown } => {
            validate_name(&name)?;
            if crate::agents::resolve(root, &name)
                .map_err(bad_config)?
                .is_some()
            {
                return Err(conflict(
                    "agent name already resolves in a configuration layer",
                ));
            }
            let target = project_agent_path(root, &name)?;
            if nofollow_read(&target)?.is_some() {
                return Err(conflict("workspace agent already exists"));
            }
            if expected_revision.is_some() {
                return Err(bad_request(
                    "create uses the daemon's authoritative absence check, not a document revision",
                ));
            }
            let parsed = crate::agents::parse_agent(
                &markdown,
                &name,
                PathBuf::from("<daemon-agent-create>"),
            )
            .map_err(bad_config)?;
            crate::agents::validate_invariants(&parsed).map_err(bad_config)?;
            std::fs::create_dir_all(target.parent().expect("agent path has parent"))
                .map_err(internal)?;
            cockpit_config::config::write_config_bytes_atomic(&target, markdown.as_bytes())
                .map_err(internal)?;
            (true, 1, Some(snapshot_sync(root, &name)?))
        }
        AgentMutation::DeleteCustom { name } => {
            validate_name(&name)?;
            if crate::agents::is_builtin_agent(&name) {
                return Err(bad_request("built-in agents cannot be deleted"));
            }
            let current = snapshot_sync(root, &name)?;
            ensure_revision(&current.revision, expected_revision.as_deref())?;
            if current.source_layer != AgentSourceLayer::Workspace {
                return Err(conflict("custom agent is not owned by the workspace layer"));
            }
            let target = project_agent_path(root, &name)?;
            if !target.is_file() {
                return Err(bad_request(
                    "custom agent is not owned by this workspace layer",
                ));
            }
            cockpit_config::config::remove_config_file_atomic(&target).map_err(internal)?;
            (true, 1, None)
        }
        AgentMutation::ResetBuiltin { name } => {
            validate_name(&name)?;
            if !crate::agents::is_builtin_agent(&name) {
                return Err(bad_request("only a built-in agent can be reset"));
            }
            let current = snapshot_sync(root, &name)?;
            ensure_revision(&current.revision, expected_revision.as_deref())?;
            if current.source_layer != AgentSourceLayer::Workspace {
                return Err(conflict(
                    "built-in override is not owned by the workspace layer",
                ));
            }
            let target = project_agent_path(root, &name)?;
            if target.is_file() {
                cockpit_config::config::remove_config_file_atomic(&target).map_err(internal)?;
                (true, 1, Some(snapshot_sync(root, &name)?))
            } else {
                (false, 0, Some(current))
            }
        }
        AgentMutation::ResetAllBuiltins => {
            let current_inventory_revision = inventory_revision(root)?;
            ensure_revision(&current_inventory_revision, expected_revision.as_deref())?;
            let affected = reset_all_builtins_atomic(root)?;
            (affected != 0, affected, None)
        }
        AgentMutation::SaveGoalSupervision { name, patch } => {
            validate_name(&name)?;
            let current = snapshot_sync(root, &name)?;
            ensure_revision(&current.revision, expected_revision.as_deref())?;
            if !matches!(
                current.source_layer,
                AgentSourceLayer::Workspace | AgentSourceLayer::Embedded
            ) {
                return Err(conflict(
                    "goal settings cannot shadow an agent owned by another configuration layer",
                ));
            }
            let mut def = crate::agents::parse_agent(
                &current.markdown,
                &name,
                PathBuf::from("<daemon-agent-goal-settings>"),
            )
            .map_err(bad_config)?;
            if def.vnext.is_some() {
                return Err(bad_request(
                    "agent-scoped goal settings are unavailable for vNext agents",
                ));
            }
            if let Some(value) = patch.cold_skeptic_count {
                def.goal_supervision.cold_skeptic_count = value;
            }
            if let Some(value) = patch.cold_skeptic_model {
                def.goal_supervision.cold_skeptic_model = value;
            }
            if let Some(value) = patch.max_verification_attempts {
                def.goal_supervision.max_verification_attempts = value;
            }
            def.goal_supervision.validate().map_err(bad_config)?;
            crate::agents::validate_invariants(&def).map_err(bad_config)?;
            let markdown = def.to_markdown().map_err(bad_config)?;
            let target = project_agent_path(root, &name)?;
            std::fs::create_dir_all(target.parent().expect("agent path has parent"))
                .map_err(internal)?;
            if markdown.as_bytes() == current.markdown.as_bytes() {
                (false, 0, Some(current))
            } else {
                cockpit_config::config::write_config_bytes_atomic(&target, markdown.as_bytes())
                    .map_err(internal)?;
                (true, 1, Some(snapshot_sync(root, &name)?))
            }
        }
    };
    let generation = if changed {
        crate::daemon::server::inventory::publish_committed_config_generation()
    } else {
        generation_before
    };
    Ok(Response::AgentMutated(AgentMutationResult {
        changed,
        affected,
        snapshot,
        config_generation: generation,
    }))
}

fn project_agent_path(root: &Path, name: &str) -> Result<PathBuf, ErrorPayload> {
    validate_name(name)?;
    let relative = format!(".cockpit/agents/{name}.md");
    crate::daemon::fs_api::resolve_authorized_canonical_path(
        root.to_string_lossy().as_ref(),
        &relative,
        crate::daemon::fs_api::AuthorizedCanonicalPathMode::WriteTarget,
    )
}

fn validate_name(name: &str) -> Result<(), ErrorPayload> {
    if name.is_empty()
        || name.len() > cockpit_proto::MAX_AGENT_NAME_BYTES
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(bad_request("agent name is invalid"));
    }
    Ok(())
}

fn revision_for(
    name: &str,
    source_layer: AgentSourceLayer,
    source_identity: &str,
    markdown: &str,
    target_exists: bool,
) -> String {
    let mut digest = Sha256::new();
    digest.update(name.as_bytes());
    digest.update(format!("{source_layer:?}").as_bytes());
    digest.update(source_identity.as_bytes());
    digest.update([u8::from(target_exists)]);
    digest.update(markdown.as_bytes());
    format!("{:x}", digest.finalize())
}

fn nofollow_read(path: &Path) -> Result<Option<Vec<u8>>, ErrorPayload> {
    cockpit_config::config::read_config_file_nofollow(path).map_err(internal)
}

fn classify_source_layer(root: &Path, source: &Path, target: &Path) -> AgentSourceLayer {
    if source == target {
        return AgentSourceLayer::Workspace;
    }
    let configured = crate::agents::agent_search_dirs(root);
    let ordinary_count = crate::config::dirs::discover_config_dirs(root).len();
    let index = configured.iter().position(|dir| source.starts_with(dir));
    if index.is_some_and(|index| index >= ordinary_count) {
        AgentSourceLayer::ConfiguredDirectory
    } else {
        AgentSourceLayer::OtherConfigLayer
    }
}

fn ensure_workspace_source_or_embedded(snapshot: &AgentEditSnapshot) -> Result<(), ErrorPayload> {
    if matches!(
        snapshot.source_layer,
        AgentSourceLayer::Workspace | AgentSourceLayer::Embedded
    ) {
        Ok(())
    } else {
        Err(conflict(
            "eject refused: another configuration layer already owns this override",
        ))
    }
}

fn opaque_source_identity(root: &Path, source: &Path, layer: AgentSourceLayer) -> String {
    let mut digest = Sha256::new();
    digest.update(root.as_os_str().as_encoded_bytes());
    digest.update(source.as_os_str().as_encoded_bytes());
    format!("{layer:?}:{:x}", digest.finalize())
}

fn inventory_revision(root: &Path) -> Result<String, ErrorPayload> {
    let mut digest = Sha256::new();
    for name in crate::agents::BUILTIN_AGENT_NAMES {
        digest.update(name.as_bytes());
        let target = project_agent_path(root, name)?;
        match nofollow_read(&target)? {
            Some(bytes) => {
                digest.update([1]);
                digest.update((bytes.len() as u64).to_le_bytes());
                digest.update(bytes);
            }
            None => digest.update([0]),
        }
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ResetAllJournal {
    operation_id: String,
    #[serde(default = "prepared_reset_phase")]
    phase: ResetAllPhase,
    /// Validated built-in agent names only. Paths and staging names are always
    /// derived by the daemon after parsing the journal.
    entries: Vec<String>,
}

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ResetAllPhase {
    Prepared,
    Committed,
}

fn prepared_reset_phase() -> ResetAllPhase {
    ResetAllPhase::Prepared
}

fn reset_journal_path(root: &Path) -> PathBuf {
    root.join(".cockpit/agent-reset-all.journal.json")
}

fn validated_reset_journal(root: &Path, raw: &[u8]) -> Result<(ResetAllJournal, PathBuf), ErrorPayload> {
    let journal: ResetAllJournal = serde_json::from_slice(raw).map_err(bad_config)?;
    let operation_id = Uuid::parse_str(&journal.operation_id)
        .map_err(|_| bad_request("agent reset journal has an invalid operation ID"))?;
    if operation_id.to_string() != journal.operation_id {
        return Err(bad_request("agent reset journal operation ID is not canonical"));
    }
    let mut seen = std::collections::HashSet::new();
    for name in &journal.entries {
        validate_name(name)?;
        if !crate::agents::is_builtin_agent(name) || !seen.insert(name.clone()) {
            return Err(bad_request("agent reset journal contains an invalid entry"));
        }
    }
    let trash_root = root.join(".cockpit/.agent-reset-trash");
    if std::fs::symlink_metadata(&trash_root)
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(bad_request("agent reset trash root is a symlink"));
    }
    let trash = trash_root.join(operation_id.to_string());
    // Reject substituted staging directories. We never recurse through this
    // path; each expected leaf is derived from a validated agent name.
    if std::fs::symlink_metadata(&trash).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(bad_request("agent reset staging directory is a symlink"));
    }
    Ok((journal, trash))
}

fn staged_agent_path(trash: &Path, name: &str) -> Result<PathBuf, ErrorPayload> {
    validate_name(name)?;
    Ok(trash.join(format!("{name}.md")))
}

fn sync_dir(path: &Path) -> Result<(), ErrorPayload> {
    cockpit_config::config::sync_directory_nofollow(path).map_err(internal)
}

/// Recover an interrupted reset conservatively by restoring every staged
/// override. A reset is externally committed only after every rename lands
/// and the journal is removed, so boot/request recovery never exposes a
/// silently partial reset as success.
fn recover_reset_all(root: &Path) -> Result<(), ErrorPayload> {
    let journal_path = reset_journal_path(root);
    let Some(raw) = nofollow_read(&journal_path)? else {
        return Ok(());
    };
    let (journal, trash) = validated_reset_journal(root, &raw)?;
    let agents_dir = root.join(".cockpit/agents");
    match journal.phase {
        ResetAllPhase::Prepared => {
            for name in journal.entries.iter().rev() {
                let target = project_agent_path(root, name)?;
                let staged = staged_agent_path(&trash, name)?;
                let staged_exists = nofollow_read(&staged)?.is_some();
                let target_exists = nofollow_read(&target)?.is_some();
                match (staged_exists, target_exists) {
                    (true, false) => std::fs::rename(&staged, &target).map_err(internal)?,
                    (true, true) => return Err(conflict("agent reset rollback found both staged and authoritative files")),
                    _ => {}
                }
            }
            if agents_dir.is_dir() { sync_dir(&agents_dir)?; }
            if trash.is_dir() { sync_dir(&trash)?; }
        }
        ResetAllPhase::Committed => {
            for name in &journal.entries {
                let staged = staged_agent_path(&trash, name)?;
                if nofollow_read(&staged)?.is_some() {
                    cockpit_config::config::remove_config_file_atomic(&staged).map_err(internal)?;
                }
            }
            if trash.is_dir() { sync_dir(&trash)?; }
        }
    }
    cockpit_config::config::remove_config_file_atomic(&journal_path).map_err(internal)?;
    sync_dir(journal_path.parent().expect("journal has parent"))?;
    if trash.is_dir() {
        std::fs::remove_dir(&trash).map_err(internal)?;
        sync_dir(trash.parent().expect("trash operation has parent"))?;
    }
    Ok(())
}

pub async fn recover_known_workspace_resets(ctx: &DaemonContext) -> Result<(), ErrorPayload> {
    let sessions = ctx
        .db
        .list_sessions(false, 100_000)
        .await
        .map_err(internal)?;
    let mut roots = std::collections::BTreeSet::new();
    roots.extend(sessions.into_iter().map(|session| session.project_root));
    let mut trusted_roots = Vec::new();
    for root in roots {
        let historical = PathBuf::from(&root);
        match std::fs::symlink_metadata(reset_journal_path(&historical)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(internal(error)),
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(bad_request("historical agent reset journal is a symlink"));
            }
            Ok(_) => {}
        }
        let root = crate::daemon::fs_api::canonical_project_root(&root)?;
        let policy = crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &root)
            .await
            .map_err(internal)?;
        if policy.mode != crate::db::workspace_trust::WorkspaceTrustMode::Trust {
            return Err(ErrorPayload {
                code: ErrorCode::PermissionDenied,
                message: format!(
                    "refusing agent reset recovery for untrusted historical root {}",
                    root.display()
                ),
            });
        }
        trusted_roots.push(root);
    }
    tokio::task::spawn_blocking(move || {
        for root in trusted_roots {
            let lock_target = root.join(".cockpit/config.json");
            let _guard = cockpit_config::config::hold_config_mutation_lock(&lock_target)
                .map_err(internal)?;
            recover_reset_all(&root)?;
        }
        Ok(())
    })
    .await
    .map_err(join_error)?
}

fn reset_all_builtins_atomic(root: &Path) -> Result<u32, ErrorPayload> {
    recover_reset_all(root)?;
    let operation_id = Uuid::new_v4();
    let trash = root.join(".cockpit/.agent-reset-trash").join(operation_id.to_string());
    let mut entries = Vec::new();
    for name in crate::agents::BUILTIN_AGENT_NAMES {
        let target = project_agent_path(root, name)?;
        if nofollow_read(&target)?.is_some() {
            entries.push((*name).to_string());
        }
    }
    if entries.is_empty() {
        return Ok(0);
    }
    if std::fs::symlink_metadata(trash.parent().expect("trash has parent"))
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(bad_request("agent reset trash root is a symlink"));
    }
    std::fs::create_dir_all(&trash).map_err(internal)?;
    let journal = ResetAllJournal {
        operation_id: operation_id.to_string(),
        phase: ResetAllPhase::Prepared,
        entries,
    };
    let encoded = serde_json::to_vec_pretty(&journal).map_err(internal)?;
    cockpit_config::config::write_config_bytes_atomic(&reset_journal_path(root), &encoded)
        .map_err(internal)?;

    let agents_dir = root.join(".cockpit/agents");
    for name in &journal.entries {
        let source = project_agent_path(root, name)?;
        let staged = staged_agent_path(&trash, name)?;
        if let Err(error) = std::fs::rename(&source, &staged) {
            // The durable journal makes rollback retryable if this immediate
            // recovery itself encounters an I/O failure.
            let _ = recover_reset_all(root);
            return Err(internal(error));
        }
    }
    sync_dir(&agents_dir)?;
    sync_dir(&trash)?;
    // The committed marker is the linearization point. Recovery before it
    // restores staged files; recovery after it finishes deletion.
    let committed = ResetAllJournal { phase: ResetAllPhase::Committed, ..journal };
    let encoded = serde_json::to_vec_pretty(&committed).map_err(internal)?;
    cockpit_config::config::write_config_bytes_atomic(&reset_journal_path(root), &encoded)
        .map_err(internal)?;
    recover_reset_all(root)?;
    Ok(committed.entries.len() as u32)
}

fn ensure_revision(current: &str, expected: Option<&str>) -> Result<(), ErrorPayload> {
    match expected {
        Some(expected) if expected == current => Ok(()),
        Some(_) => Err(conflict("agent changed since the snapshot was read")),
        None => Err(conflict("agent mutation requires an expected revision")),
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

fn bad_config(error: impl std::fmt::Display) -> ErrorPayload {
    bad_request(format!("invalid agent definition: {error}"))
}

fn internal(error: impl std::fmt::Display) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::Internal,
        message: format!("agent management failed: {error}"),
    }
}

fn join_error(error: tokio::task::JoinError) -> ErrorPayload {
    internal(format!("agent management worker failed: {error}"))
}

fn lock_poison<T>(_: std::sync::PoisonError<T>) -> ErrorPayload {
    internal("agent editor lease registry is unavailable")
}
