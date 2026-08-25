//! Atomic daemon inventory-bundle projection.
//!
//! One immutable [`InventorySourceSnapshot`] is acquired by dispatch, then
//! projected into agents, models, and selected-agent skills without
//! rediscovering config. Response bounds fail closed with typed errors and
//! no partial rows.

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use cockpit_config::config::providers::{ModelEntry, ProviderEntry, ProvidersConfig, ThinkingMode};
use cockpit_config::config::trust::WorkspaceTrustPolicy;
use uuid::Uuid;

use crate::daemon::proto::{
    AgentSummary, ErrorCode, ErrorPayload, ModelSummary, Response, SkillSummary,
};

/// Hard caps for a single inventory-bundle response. Exceeding any bound
/// returns [`ErrorCode::InventoryTooLarge`] with zero partial rows.
pub const MAX_INVENTORY_AGENTS: usize = 512;
pub const MAX_INVENTORY_MODELS: usize = 8_192;
pub const MAX_INVENTORY_SKILLS: usize = 4_096;
pub const MAX_INVENTORY_ENCODED_BYTES: usize = 4 * 1024 * 1024;

/// Process-wide inventory generation additive; advances on config-driven
/// inventory source changes. Combined with the skills catalog generation.
static INVENTORY_GENERATION: AtomicU64 = AtomicU64::new(0);
static CONFIG_GENERATION: AtomicU64 = AtomicU64::new(0);
/// A generation is meaningful only together with the authority projection it
/// labels. Readers hold the shared side while collecting rows and the
/// generation; agent/assistant writers hold the exclusive side from their CAS
/// read through durable publication and the generation bump. This closes the
/// commit-before-bump window that an atomic counter alone cannot close.
static AUTHORITY_PUBLICATION_FENCE: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

pub async fn read_authority_publication() -> tokio::sync::RwLockReadGuard<'static, ()> {
    AUTHORITY_PUBLICATION_FENCE.read().await
}

pub async fn write_authority_publication() -> tokio::sync::RwLockWriteGuard<'static, ()> {
    AUTHORITY_PUBLICATION_FENCE.write().await
}

type InventoryBarrierCb = Box<dyn Fn() + Send + Sync>;

/// Test-only barriers observed at every collection boundary so atomicity tests
/// can prove a bundle is wholly old or wholly new.
#[derive(Default)]
struct InventoryBarriers {
    after_acquire: Option<InventoryBarrierCb>,
    after_agents: Option<InventoryBarrierCb>,
    after_models: Option<InventoryBarrierCb>,
    after_skills: Option<InventoryBarrierCb>,
    after_encode: Option<InventoryBarrierCb>,
}

static INVENTORY_BARRIERS: Mutex<InventoryBarriers> = Mutex::new(InventoryBarriers {
    after_acquire: None,
    after_agents: None,
    after_models: None,
    after_skills: None,
    after_encode: None,
});

/// Advance the inventory generation counter (config refresh, skill invalidation).
pub fn bump_inventory_generation() -> u64 {
    INVENTORY_GENERATION.fetch_add(1, Ordering::SeqCst) + 1
}

pub fn current_inventory_generation() -> u64 {
    // Skills catalog generation advances independently when SKILL.md trees
    // change; combine so either source advances the inventory floor.
    INVENTORY_GENERATION
        .load(Ordering::SeqCst)
        .saturating_add(crate::skills::catalog_generation())
}

pub fn current_config_generation() -> u64 {
    CONFIG_GENERATION.load(Ordering::SeqCst)
}

/// A stable-per-boot daemon instance identifier, lazily minted on first read.
/// Used as the `daemonInstanceId` in image-control read replies so a client can
/// tell a snapshot apart across daemon restarts. A restart mints a fresh value
/// (fail-closed: cursors/snapshots from a prior boot are not revived).
pub fn daemon_instance_id() -> &'static str {
    static DAEMON_INSTANCE_ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DAEMON_INSTANCE_ID.get_or_init(|| Uuid::new_v4().to_string())
}

pub fn compare_and_bump_config_generation(expected: u64) -> Option<u64> {
    let next = expected.checked_add(1)?;
    CONFIG_GENERATION
        .compare_exchange(expected, next, Ordering::SeqCst, Ordering::SeqCst)
        .ok()?;
    bump_inventory_generation();
    Some(next)
}

/// Publish a configuration change only after its durable commit succeeds.
/// This operation cannot fail due to an unrelated concurrent publisher: each
/// successful commit receives a distinct monotonically increasing generation.
pub fn publish_committed_config_generation() -> u64 {
    let generation = CONFIG_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
    bump_inventory_generation();
    generation
}

#[cfg(test)]
pub fn install_inventory_barriers(
    after_acquire: Option<Box<dyn Fn() + Send + Sync>>,
    after_agents: Option<Box<dyn Fn() + Send + Sync>>,
    after_models: Option<Box<dyn Fn() + Send + Sync>>,
    after_skills: Option<Box<dyn Fn() + Send + Sync>>,
    after_encode: Option<Box<dyn Fn() + Send + Sync>>,
) {
    let mut guard = INVENTORY_BARRIERS.lock().expect("inventory barriers");
    *guard = InventoryBarriers {
        after_acquire,
        after_agents,
        after_models,
        after_skills,
        after_encode,
    };
}

#[cfg(test)]
pub fn clear_inventory_barriers() {
    install_inventory_barriers(None, None, None, None, None);
}

fn run_barrier(slot: fn(&InventoryBarriers) -> &Option<InventoryBarrierCb>) {
    let guard = INVENTORY_BARRIERS.lock().expect("inventory barriers");
    if let Some(cb) = slot(&guard) {
        cb();
    }
}

/// Immutable inputs for one atomic inventory projection.
#[derive(Clone)]
pub struct InventorySourceSnapshot {
    pub project_root: PathBuf,
    #[allow(dead_code)] // stamped for client correlation / future authz checks
    pub session_id: Uuid,
    pub selected_agent: String,
    pub session_generation: u64,
    pub config_generation: u64,
    pub inventory_generation: u64,
    pub trust_policy: WorkspaceTrustPolicy,
    pub providers: ProvidersConfig,
    pub skills_config: crate::config::extended::SkillsConfig,
    /// Pre-resolved chat-ownable primary names under the snapshot trust policy.
    pub ownable_agents: Vec<String>,
}

/// Pure projection of one source snapshot into a wire inventory bundle.
pub fn project_inventory_bundle(
    snapshot: &InventorySourceSnapshot,
) -> Result<Response, ErrorPayload> {
    run_barrier(|b| &b.after_acquire);

    if !snapshot
        .ownable_agents
        .iter()
        .any(|name| name == &snapshot.selected_agent)
    {
        return Err(ErrorPayload {
            code: ErrorCode::UnknownAgent,
            message: format!(
                "agent `{}` is not a chat-ownable primary in the inventory snapshot",
                snapshot.selected_agent
            ),
        });
    }

    let agents = project_agents(snapshot)?;
    run_barrier(|b| &b.after_agents);
    if agents.len() > MAX_INVENTORY_AGENTS {
        return Err(inventory_too_large(format!(
            "agent count {} exceeds cap {MAX_INVENTORY_AGENTS}",
            agents.len()
        )));
    }

    let models = project_models(snapshot)?;
    run_barrier(|b| &b.after_models);
    if models.len() > MAX_INVENTORY_MODELS {
        return Err(inventory_too_large(format!(
            "model count {} exceeds cap {MAX_INVENTORY_MODELS}",
            models.len()
        )));
    }

    let skills = project_skills(snapshot)?;
    run_barrier(|b| &b.after_skills);
    if skills.len() > MAX_INVENTORY_SKILLS {
        return Err(inventory_too_large(format!(
            "skill count {} exceeds cap {MAX_INVENTORY_SKILLS}",
            skills.len()
        )));
    }

    let response = Response::InventoryBundle {
        selected_agent: snapshot.selected_agent.clone(),
        agents,
        models,
        skills,
        session_generation: snapshot.session_generation,
        config_generation: snapshot.config_generation,
        inventory_generation: snapshot.inventory_generation,
    };
    run_barrier(|b| &b.after_encode);

    let encoded = serde_json::to_vec(&response).map_err(|err| ErrorPayload {
        code: ErrorCode::Internal,
        message: format!("{err:#}"),
    })?;
    if encoded.len() > MAX_INVENTORY_ENCODED_BYTES {
        return Err(inventory_too_large(format!(
            "encoded inventory size {} exceeds cap {MAX_INVENTORY_ENCODED_BYTES}",
            encoded.len()
        )));
    }
    Ok(response)
}

fn inventory_too_large(message: String) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::InventoryTooLarge,
        message,
    }
}

fn agent_mode_summary(definition: &crate::agents::AgentDef) -> &'static str {
    match definition.vnext.as_ref().map(|vnext| vnext.execution_kind) {
        Some(crate::agents::ExecutionKind::Assistant) => "assistant",
        Some(crate::agents::ExecutionKind::Coding) => "coding",
        Some(crate::agents::ExecutionKind::Computer) => "computer",
        None => match definition.mode {
            crate::agents::AgentMode::Primary => "primary",
            crate::agents::AgentMode::Subagent => "subagent",
            crate::agents::AgentMode::All => "all",
        },
    }
}

fn validate_ownable(name: &str, ownable: &[String]) -> Result<(), ErrorPayload> {
    if !ownable.iter().any(|agent| agent == name) {
        return Err(ErrorPayload {
            code: ErrorCode::UnknownAgent,
            message: format!(
                "agent `{name}` is not a chat-ownable primary in the inventory snapshot"
            ),
        });
    }
    Ok(())
}

fn project_agents(snapshot: &InventorySourceSnapshot) -> Result<Vec<AgentSummary>, ErrorPayload> {
    let mut agents = Vec::with_capacity(snapshot.ownable_agents.len());
    for name in &snapshot.ownable_agents {
        validate_ownable(name, &snapshot.ownable_agents)?;
        let def = crate::config::trust::with_workspace_trust_policy(
            snapshot.trust_policy.clone(),
            || crate::agents::resolve(&snapshot.project_root, name),
        )
        .map_err(|err| ErrorPayload {
            code: ErrorCode::Internal,
            message: format!("{err:#}"),
        })?
        .ok_or_else(|| ErrorPayload {
            code: ErrorCode::Internal,
            message: format!("chat-ownable agent `{name}` did not resolve"),
        })?;
        let mode = agent_mode_summary(&def).to_string();
        agents.push(AgentSummary {
            builtin: crate::agents::is_builtin_agent(name),
            name: name.clone(),
            description: def.description,
            mode,
            source: def.source.display().to_string(),
        });
    }
    Ok(agents)
}

fn project_models(snapshot: &InventorySourceSnapshot) -> Result<Vec<ModelSummary>, ErrorPayload> {
    let providers = &snapshot.providers;
    let mut models = Vec::new();
    for (provider_id, provider) in &providers.providers {
        for model in &provider.models {
            models.push(project_model_summary(
                providers,
                provider_id,
                provider,
                model,
            ));
        }
    }
    models.sort_by(|a, b| {
        b.favorite
            .cmp(&a.favorite)
            .then_with(|| a.provider.cmp(&b.provider))
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(models)
}

fn project_model_summary(
    providers: &ProvidersConfig,
    provider_id: &str,
    provider: &ProviderEntry,
    model: &ModelEntry,
) -> ModelSummary {
    let native_anthropic =
        cockpit_config::config::providers::is_anthropic_native_base_url(&provider.url);
    let native_provider_valid = if native_anthropic {
        cockpit_config::config::providers::validate_anthropic_model_configuration(
            provider, &model.id,
        )
        .is_ok()
    } else {
        true
    };

    let reasoning_effort = if native_anthropic && !native_provider_valid {
        None
    } else {
        model
            .capabilities
            .reasoning_effort
            .clone()
            .filter(|c| !c.is_empty())
    };

    let thinking_modes: Vec<ThinkingMode> = if native_anthropic {
        Vec::new()
    } else {
        model.thinking_modes.clone()
    };

    let trust = providers.resolve_trust(provider_id, &model.id);
    let available = model_available(provider, model);

    ModelSummary {
        provider: provider_id.to_string(),
        id: model.id.clone(),
        display_name: model.name.clone(),
        favorite: model.favorite,
        trust,
        reasoning_effort,
        thinking_modes,
        available,
        native_provider_valid,
    }
}

fn model_available(provider: &ProviderEntry, model: &ModelEntry) -> bool {
    provider.availability.permits(None, None, None) && model.availability.permits(None, None, None)
}

fn project_skills(snapshot: &InventorySourceSnapshot) -> Result<Vec<SkillSummary>, ErrorPayload> {
    let def =
        crate::config::trust::with_workspace_trust_policy(snapshot.trust_policy.clone(), || {
            crate::agents::resolve(&snapshot.project_root, &snapshot.selected_agent)
        })
        .map_err(|err| ErrorPayload {
            code: ErrorCode::Internal,
            message: format!("{err:#}"),
        })?
        .ok_or_else(|| ErrorPayload {
            code: ErrorCode::UnknownAgent,
            message: format!(
                "agent `{}` did not resolve in the inventory snapshot",
                snapshot.selected_agent
            ),
        })?;

    let tool_names: Vec<String> = def.tools.clone().unwrap_or_default();
    let activation =
        crate::skills::ActivationContext::from_tool_names(tool_names.iter().map(String::as_str));
    let skills = crate::skills::discover_for_session(
        &snapshot.project_root,
        &snapshot.skills_config,
        &activation,
    )
    .map_err(|err| ErrorPayload {
        code: ErrorCode::Internal,
        message: format!("{err:#}"),
    })?;

    let mut out: Vec<SkillSummary> = skills
        .into_iter()
        .filter(|s| s.frontmatter.user_invocable)
        .map(|s| SkillSummary {
            name: s.frontmatter.name,
            description: s.frontmatter.description,
            source: s.source.display().to_string(),
            user_invocable: s.frontmatter.user_invocable,
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}
