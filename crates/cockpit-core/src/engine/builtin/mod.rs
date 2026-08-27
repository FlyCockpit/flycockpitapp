//! Built-in agent definitions: `Build`, `builder`.
//!
//! The agent prompts live as Markdown documents alongside this file.
//! `include_str!` bakes them into the binary so a fresh `cargo install
//! cockpit-cli` ships with the bundled cast (GOALS §3a). User-authored
//! agents go through [`crate::agents`] / `agent_dirs`; they're the
//! extension path.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail, ensure};

use crate::engine::agent::Agent;
use crate::engine::model::{Model, ModelParams};
use crate::engine::tool::ToolBox;
use crate::model_system_prompt::ModelSystemPromptSnapshot;
use crate::tools::custom::{CustomBashTool, ToolTemplateProvenance};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationRecursionContext {
    pub enabled: bool,
    pub remaining_depth: u32,
    pub allowed_targets: Vec<String>,
    pub same_model_only: bool,
}

impl Default for DelegationRecursionContext {
    fn default() -> Self {
        Self {
            enabled: true,
            remaining_depth: 0,
            allowed_targets: Vec::new(),
            same_model_only: false,
        }
    }
}

impl DelegationRecursionContext {
    pub fn can_delegate_to(&self, target: &str) -> bool {
        self.enabled
            && self.remaining_depth > 0
            && self.allowed_targets.iter().any(|allowed| allowed == target)
    }
}

pub fn configured_recursion_context(
    cfg: &crate::config::extended::DelegationConfig,
    agent: &str,
    remaining_depth: Option<u32>,
) -> DelegationRecursionContext {
    let policy = cfg.recursion.get(agent).or_else(|| cfg.recursion.get("*"));
    let configured_remaining = remaining_depth.unwrap_or_else(|| {
        policy
            .and_then(|policy| policy.default_depth)
            .unwrap_or(cfg.default_recursion_depth)
    });
    let max_depth = policy.and_then(|policy| policy.max_depth);
    let allowed_targets = policy
        .map(|policy| policy.allowed_targets.clone())
        .unwrap_or_default();
    DelegationRecursionContext {
        enabled: cfg.recursion_enabled,
        remaining_depth: max_depth
            .map(|max| configured_remaining.min(max))
            .unwrap_or(configured_remaining),
        allowed_targets,
        same_model_only: false,
    }
}

/// Embedded prompt for `Build`. The frontmatter is
/// authored opencode-style for forward-compat with [`crate::agents`]
/// — we still pull the prompt out by hand here because the agent loop
/// already knows the tool surface.
// Issue #75: each bundled agent has a single canonical prompt body in the
// flat `<name>.md` file. Per-model-slot overrides live on the AgentDef as
// `prompt_overrides` (`<name>/<key>.md`).
pub(crate) const BUILD_PROMPT: &str = include_str!("build.md");
pub(crate) const CAREFUL_PROMPT: &str = include_str!("careful.md");
pub(crate) const BUILDER_PROMPT: &str = include_str!("builder.md");
pub(crate) const EXPLORE_PROMPT: &str = include_str!("explore.md");
pub(crate) const HISTORY_PROMPT: &str = include_str!("history.md");
pub(crate) const DEEPTHINK_PROMPT: &str = include_str!("deepthink.md");
pub(crate) const SCOUT_PROMPT: &str = include_str!("scout.md");
pub(crate) const PLAN_PROMPT: &str = include_str!("plan.md");
pub(crate) const MULTIREVIEW_PROMPT: &str = include_str!("multireview.md");
// `bee` — `Swarm`'s recursive parallel worker (GOALS §24/§26).
pub(crate) const BEE_PROMPT: &str = include_str!("bee.md");
pub(crate) const COMPUTER_PROMPT: &str = "You are the computer-use subagent. Use the provider-native computer tool to inspect and operate the display only for the delegated task. Report concise progress and stop when the delegated display work is complete.";

/// Docs pipeline stage prompts (GOALS §3a, prompt `docs-agent.md`).
pub(crate) const DOCS_RESOLVER_PROMPT: &str = include_str!("docs_resolver.md");
pub(crate) const DOCS_ANSWERER_PROMPT: &str = include_str!("docs_answerer.md");

/// Per-spawn knobs threaded from the driver.
#[derive(Clone)]
pub struct SpawnArgs {
    pub model: Arc<Model>,
    pub params: ModelParams,
    pub env_overlay: Arc<std::sync::RwLock<std::collections::HashMap<String, String>>>,
    /// Session cwd — used to discover the layered `config.json`
    /// so user-defined custom-bash tools (`webfetch`, `websearch`, …)
    /// land on the toolbox for agents that should see them.
    pub cwd: std::path::PathBuf,
    /// Session config reader (`engine-config-snapshot-adoption`). Agent
    /// factories resolve web/custom-tool, computer, delegation-model, and
    /// deepthink config from this snapshot rather than re-reading disk, so a
    /// delegated child built mid-turn sees the same generation as the turn.
    pub config: crate::daemon::session_worker::SessionConfigHandle,
    /// 6-char session display id (GOALS §17b). Appended to the cached
    /// system prompt (§17g) so the model knows which conversation it
    /// is participating in. Empty string is acceptable for legacy /
    /// test paths where a session id isn't yet resolved.
    pub session_short_id: String,
    /// Assistant-owned sessions prepend SOUL.md and USER.md before the
    /// assistant definition body. Preloaded by the session worker so prompt
    /// composition stays pure and stable for the session.
    pub assistant_identity_prefix: Option<String>,
    /// Frozen model-specific prompt snapshot for this session/invocation.
    pub model_system_prompt_snapshot: Arc<ModelSystemPromptSnapshot>,
    /// Whether this agent is being spawned into a user-facing
    /// interactive session (the daemon root, or an interactive handoff
    /// such as `builder`) versus a one-shot leaf delegation
    /// (`run_noninteractive`) or the `docs` pipeline. Gates the
    /// cross-session recall tools (`session_search` / `session_read`):
    /// they're registered only when `true`, so non-interactive contexts
    /// don't pay their description tokens (token economy, GOALS §10).
    /// This is the spawn-time analog of the runtime
    /// [`crate::engine::interrupt::InterruptHub::is_interactive_attached`]
    /// gate — the existing interactive-mode signal, not a new one.
    pub interactive: bool,
    /// Root selection (explicit fresh choice, persisted installed-root resume,
    /// or legacy plan-level override). A delegated vNext child never inherits
    /// this field: it resolves its own prepared slot default unless its direct
    /// parent supplies [`Self::delegation_model`]. Keeping these two fields
    /// separate preserves the authority/provenance of an explicit parent
    /// choice.
    pub model_override: Option<Arc<Model>>,
    /// Optional structured model selector supplied by the delegating agent on
    /// `task`; honored only when the config toggle allows it.
    pub delegation_model: Option<crate::engine::model_roles::DelegationModelSelector>,
    /// Whether this spawn is a delegated child rather than a root/primary
    /// session agent. Delegated children only get recursive `task` affordances
    /// when [`delegation_recursion`] permits them.
    pub delegated: bool,
    /// Effective remaining recursive `task` budget and target allow-list for
    /// this spawn. Primaries may still perform their normal first-level
    /// delegation; this context governs delegation by delegated children.
    pub delegation_recursion: DelegationRecursionContext,
    /// Host-resolved vNext authority snapshotted for this spawn.  A markdown
    /// definition is only a request; factories must never derive `task` from
    /// its raw `delegation` block.  The driver/installation resolver owns
    /// producing this value for the selected definition and carries it to a
    /// child unchanged (or reduced) for the duration of a task.
    pub vnext_grant: Option<crate::agents::EffectiveVnextGrant>,
    /// Host policy snapshot used only to calculate a child grant from the
    /// parent frame's already-effective vNext grant. A missing policy means
    /// vNext is unavailable rather than inferred from markdown.
    pub vnext_host_policy: Option<std::sync::Arc<crate::agents::VnextHostPolicy>>,
    /// Exact daemon-owned local-installation bindings.  This is intentionally
    /// empty by default: local UUID references fail closed unless the session
    /// installation owner injects a binding for that UUID.
    pub vnext_local_installation_resolver: crate::agents::LocalInstallationResolver,
    /// Effective authority of the direct parent. This is distinct from
    /// `vnext_grant`, which is the grant for the definition currently being
    /// built; separating them prevents a parent grant being replayed as a
    /// child's grant.
    pub parent_vnext_grant: Option<crate::agents::EffectiveVnextGrant>,
    /// Effective posture of the direct parent. Delegated construction
    /// intersects the child's declared grants with this set so authority can
    /// never widen down the agent tree.
    pub parent_posture: Option<crate::agents::PostureResolution>,
    /// Recursive-`Swarm` depth of the agent being spawned (GOALS §24):
    /// levels of Swarm-spawning-Swarm, root = 0. Used to bake the
    /// effective per-task depth into the `spawn` tool description so
    /// the model can self-limit, and to gate spawns at the ceiling. `0` for
    /// every non-`Swarm` spawn (depth only advances along Swarm edges).
    pub swarm_depth: u32,
    /// The `Swarm` depth ceiling (GOALS §24, `swarm.max_depth`). Baked
    /// into the `spawn` description alongside `swarm_depth` so the
    /// model sees how much recursion budget remains.
    pub swarm_max_depth: u32,
    /// Per-delegation **tool grants** (prompt `parent-granted-tools.md`): extra
    /// tools a parent attached to *this one* `task` delegation so the child's
    /// effective surface = its base def + these grants, for this run only.
    /// Empty for every non-delegation spawn and for delegations without a grant.
    /// Validated against the role invariants
    /// ([`crate::agents::invariants::validate_grant`]) **before** the spawn, so
    /// a grant that reaches a factory is already admissible. A child is a fresh
    /// context, so its tool set (base + grants) is fixed here at spawn —
    /// satisfying the cache-safety rule per child-run; grants never persist or
    /// leak because each spawn builds a fresh [`SpawnArgs`].
    pub granted_tools: Vec<String>,
    /// Per-instance lock identity. Defaults to the spawned agent name; scoped
    /// parallel task children set this to `<agent>#<label>`.
    pub lock_identity: Option<String>,
    /// Optional write-confined subtree for delegated children. Native writes
    /// and shell sandboxes enforce this; reads remain cwd-wide.
    pub write_scope: Option<std::path::PathBuf>,
    /// Vault-backed credential store for delegated model construction.
    /// Production session/driver spawns pass `Some`; tests may leave `None`.
    pub credential_store: Option<crate::credentials::CredentialStore>,
}

impl SpawnArgs {
    /// The model an agent factory should spawn under: the plan-level override
    /// when present, else the session model. This is the precedence floor —
    /// the per-agent frontmatter `model` (handled in [`resolve_agent_model`])
    /// applies only when there is no plan-level override.
    fn effective_model(&self) -> Arc<Model> {
        self.model_override
            .clone()
            .unwrap_or_else(|| self.model.clone())
    }
}

#[derive(Debug, Clone, PartialEq)]
struct ResolvedComputerUse {
    tier: crate::config::extended::ComputerUseMode,
    native_computer: Option<crate::computer::NativeComputerToolConfig>,
    requires_approval: bool,
}

fn default_computer_geometry() -> crate::computer::DisplayGeometry {
    crate::computer::DisplayGeometry {
        physical: crate::computer::PixelSize {
            width: 1024,
            height: 768,
        },
        logical: crate::computer::LogicalSize {
            width: 1024.0,
            height: 768.0,
        },
        scale_factor: crate::computer::ScaleFactor(1.0),
    }
}

fn resolved_computer_use_for_model(
    providers: &crate::config::providers::ProvidersConfig,
    cwd: &Path,
    model: &Model,
) -> ResolvedComputerUse {
    let configured = crate::config::extended::resolve_computer_use_policy_for_cwd(cwd);
    let tier = providers.resolve_computer_use_effective(
        model.provider_id(),
        model.model_id_ref(),
        configured,
        None,
    );
    let caps = providers.resolve_effective_model_capabilities(
        model.provider_id(),
        model.model_id_ref(),
        providers.resolution_generation,
    );
    let native_computer = (tier != crate::config::extended::ComputerUseMode::Disabled
        && caps.supports_image_input())
    .then(|| {
        caps.computer_use
            .and_then(|capability| capability.contract)
            .map(|contract| crate::computer::NativeComputerToolConfig {
                contract: contract.into(),
                geometry: default_computer_geometry(),
                approval_required: tier == crate::config::extended::ComputerUseMode::Ask,
            })
    })
    .flatten();
    ResolvedComputerUse {
        tier,
        native_computer,
        requires_approval: tier == crate::config::extended::ComputerUseMode::Ask,
    }
}

fn params_with_direct_computer(args: &SpawnArgs, model: &Model) -> ModelParams {
    let mut params = args.params.clone();
    let providers = args.config.providers();
    params.native_computer =
        resolved_computer_use_for_model(&providers, &args.cwd, model).native_computer;
    params
}

/// Build and resolve the custody-typed route for one computer-use candidate.
///
/// Screenshots and desktop context are a potentially sensitive payload, so this
/// path may not omit custody. The class is the candidate's own configured trust
/// class — host-authorized, because enabling `computer_use` on a model is a
/// host configuration decision and no model-authored selector reaches here.
pub(crate) fn computer_use_custody_route(
    providers: &crate::config::providers::ProvidersConfig,
    provider_id: &str,
    model_id: &str,
) -> Result<crate::config::providers::ResolvedModelPolicy, crate::config::providers::ModelPolicyError>
{
    let custody = crate::engine::model_roles::custody_for_trust(
        providers.resolve_trust(provider_id, model_id),
    );
    // Eligibility only — no payload is constructed, so this decision can never
    // be used to render anything through an identity no-op table. The worker
    // construction site builds the paired custody/payload request instead.
    let selector = format!("{provider_id}:{model_id}");
    providers.resolve_sensitive_model_policy_eligibility(&computer_use_criteria(&selector), custody)
}

/// The shared selection criteria for a computer-use route, so the candidate
/// scan and the worker construction site cannot drift apart.
pub(crate) fn computer_use_criteria(
    selector: &str,
) -> crate::config::providers::ModelPolicyCriteria<'_> {
    use crate::config::providers::{
        AvailabilityScope, ModelOptimization, ModelPolicyCriteria, ModelPolicySelector,
        RequiredModelCapability,
    };
    ModelPolicyCriteria {
        selector: ModelPolicySelector::Exact(selector),
        required_capabilities: vec![RequiredModelCapability::ImageInput],
        min_context_tokens: None,
        require_subagent_invokable: true,
        optimize: ModelOptimization::Balanced,
        role: Some("computer"),
        agent: Some("computer"),
        // The host enabled `computer_use` on this exact model.
        availability: AvailabilityScope::HostNamedTarget,
    }
}

fn computer_subagent_candidate(
    providers: &crate::config::providers::ProvidersConfig,
    cwd: &Path,
) -> Option<(String, String, crate::computer::NativeComputerToolConfig)> {
    let configured = crate::config::extended::resolve_computer_use_policy_for_cwd(cwd);
    for (provider_id, provider) in &providers.providers {
        for model in &provider.models {
            let tier =
                providers.resolve_computer_use_effective(provider_id, &model.id, configured, None);
            if tier == crate::config::extended::ComputerUseMode::Disabled {
                continue;
            }
            if !providers.resolve_subagent_invokable(provider_id, &model.id) {
                continue;
            }
            let caps = providers.resolve_effective_model_capabilities(
                provider_id,
                &model.id,
                providers.resolution_generation,
            );
            if !caps.supports_image_input() {
                continue;
            }
            let Some(contract) = caps.computer_use.and_then(|capability| capability.contract)
            else {
                continue;
            };
            // Computer use ships screenshots of the user's desktop — a
            // potentially sensitive payload — so the route is custody-typed.
            // The custody class is the configured computer-use model's own
            // trust class: the host authorized this model for computer use, a
            // model never picks it.
            if computer_use_custody_route(providers, provider_id, &model.id).is_err() {
                continue;
            }
            return Some((
                provider_id.clone(),
                model.id.clone(),
                crate::computer::NativeComputerToolConfig {
                    contract: contract.into(),
                    geometry: default_computer_geometry(),
                    approval_required: tier == crate::config::extended::ComputerUseMode::Ask,
                },
            ));
        }
    }
    None
}

fn computer_subagent_reachable(
    config: &crate::daemon::session_worker::SessionConfigHandle,
    cwd: &Path,
) -> bool {
    let (_extended, providers) = config.configs();
    computer_subagent_candidate(&providers, cwd).is_some()
}

/// Append the direct full codebase-intelligence tool set (GOALS §21) to `tb`.
/// Used by read-worker surfaces whose current tier defaults keep the graph
/// tail directly callable.
fn with_full_intel(tb: ToolBox) -> ToolBox {
    with_core_intel(tb)
        .with(Arc::new(crate::tools::intel::GraphTool))
        .with(Arc::new(crate::tools::intel::ChangeImpactTool))
}

fn with_core_intel(tb: ToolBox) -> ToolBox {
    tb.with(Arc::new(crate::tools::intel::ContextPackTool))
        .with(Arc::new(crate::tools::intel::CodeTool))
        .with(Arc::new(crate::tools::intel::SearchTool))
}

fn with_build_family_intel(tb: ToolBox) -> ToolBox {
    with_core_intel(tb)
        .with_discoverable_mcp(Arc::new(crate::tools::intel::GraphTool))
        .with_discoverable_mcp(Arc::new(crate::tools::intel::ChangeImpactTool))
}

fn with_lsp_nav(tb: ToolBox) -> ToolBox {
    tb.with(Arc::new(crate::tools::lsp::LspTool))
}

/// Append the single-writer file-mutation + lock tools to `tb`. Any agent that
/// holds these is **write-capable** (the definition is structural — holding
/// these tools — not a hard-coded name, `agents::invariants::LOCK_WRITE_TOOLS`).
/// Their writes are arbitrated by the single in-daemon lock authority
/// (`crate::locks`), path-granular and keyed by `(session, agent)`, so the
/// multiple write-capable agents (`Build`/`builder`/`Swarm`/`bee`) coexist on
/// disjoint paths while a same-path write is serialized/rejected.
fn with_write_tools(tb: ToolBox) -> ToolBox {
    tb.with(Arc::new(crate::tools::read::ReadTool))
        .with(Arc::new(crate::tools::write::WriteTool))
        .with(Arc::new(crate::tools::edit::EditTool))
        .with(Arc::new(crate::tools::unlock::UnlockTool))
}

/// Append the cross-session recall tools (`session_search` /
/// `session_read`, prompt `search-old-sessions.md`) to `tb` when this
/// spawn is interactive. Centralized so every user-facing agent shares
/// one gate rather than each re-spelling the pair + the `interactive`
/// check.
fn with_recall_tools(tb: ToolBox, args: &SpawnArgs) -> ToolBox {
    if !args.interactive {
        return tb;
    }
    tb.with(Arc::new(crate::tools::session_search::SessionSearchTool))
        .with(Arc::new(crate::tools::session_read::SessionReadTool))
        .with(Arc::new(crate::tools::todo::TodoTool))
}

fn with_tiered_recall_tools(
    mut tb: ToolBox,
    args: &SpawnArgs,
    def: &crate::agents::AgentDef,
    is_assistant: bool,
    grant: &[String],
) -> Result<ToolBox> {
    if !args.interactive {
        return Ok(tb);
    }
    let grant_has_mcp = grant.iter().any(|tool| tool == "mcp");
    for name in [
        "session_search",
        "session_read",
        "session_lineage_search",
        "todo",
    ] {
        if is_assistant
            && !grant_has_mcp
            && !grant.iter().any(|tool| tool == name)
            && default_assistant_discoverable_tools().contains(&name)
        {
            continue;
        }
        tb = match effective_tool_tier(def, name, is_assistant) {
            crate::agents::ToolTier::Enabled => add_tool_by_name(tb, name, def, args)?,
            crate::agents::ToolTier::Discoverable => {
                add_discoverable_tool_by_name(tb, name, def, args)?
            }
            crate::agents::ToolTier::Disabled => tb,
        };
    }
    Ok(tb)
}

fn with_task_for_targets(tb: ToolBox, args: &SpawnArgs, targets: &[&str]) -> ToolBox {
    let allowed: Vec<&str> = if args.delegated && args.vnext_grant.is_none() {
        targets
            .iter()
            .copied()
            .filter(|target| args.delegation_recursion.can_delegate_to(target))
            .collect()
    } else {
        targets.to_vec()
    };
    if allowed.is_empty() {
        return tb;
    }
    if args.delegated && args.vnext_grant.is_none() {
        tb.with(Arc::new(
            crate::tools::task::TaskTool::with_recursive_subagents(
                &allowed,
                args.delegation_recursion.remaining_depth,
                args.delegation_recursion.same_model_only,
            ),
        ))
    } else {
        tb.with(Arc::new(crate::tools::task::TaskTool::with_subagents(
            &allowed,
        )))
    }
}

/// Every native tool name that an agent definition may mention in `tools:`.
/// Materialization flows through [`materialize_tool_by_name`] so validation,
/// grants, and markdown-agent construction do not drift apart.
pub(crate) fn known_agent_tool_names() -> &'static [&'static str] {
    &[
        "read",
        "bash",
        "escalate",
        "context_pack",
        "code",
        "graph",
        "search",
        "change_impact",
        "task",
        "skill",
        "skill_manage",
        "question",
        "schedule",
        "spawn",
        "mcp",
        "webfetch",
        "websearch",
        "lsp",
        "plan_read",
        "plan_write",
        "plan_edit",
        "start_build",
        "defer_to_orchestrator",
        "return",
        "harness_list",
        "harness_invoke",
        "session_search",
        "session_read",
        "session_lineage_search",
        "todo",
        "write",
        "edit",
        "unlock",
        "grep",
        "glob",
        "use_sealed_value",
        "inspect_audio",
        "inspect_video",
        "extract_video_clip",
        "extract_audio",
        "transcribe_audio",
        "read_image",
        "ask_image",
        #[cfg(feature = "extended")]
        "list_image_generation_targets",
        #[cfg(feature = "extended")]
        "generate_image",
        #[cfg(feature = "extended")]
        "get_image_generation_job",
        #[cfg(feature = "extended")]
        "cancel_image_generation_job",
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltinToolInventoryItem {
    pub family: &'static str,
    pub name: &'static str,
    pub summary: &'static str,
    pub condition: Option<&'static str>,
}

/// Read-only inventory of native tool names grouped for UI/settings surfaces.
///
/// Keep this list next to [`known_agent_tool_names`] and
/// [`materialize_tool_by_name`] so agent grants, runtime materialization, and
/// user-facing inventory drift together instead of each UI re-spelling names.
pub fn builtin_tool_inventory() -> &'static [BuiltinToolInventoryItem] {
    &[
        BuiltinToolInventoryItem {
            family: "Filesystem",
            name: "read",
            summary: "Read project files through the sandbox boundary.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Filesystem",
            name: "grep",
            summary: "Search file contents with scoped regular expressions.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Filesystem",
            name: "glob",
            summary: "Find files by glob pattern.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Shell",
            name: "bash",
            summary: "Run shell commands with approval and sandbox checks.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Shell",
            name: "escalate",
            summary: "Request elevated command or path access from the user.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Locks",
            name: "write",
            summary: "Write files with automatic daemon-arbitrated locking.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Locks",
            name: "edit",
            summary: "Edit files with automatic daemon-arbitrated locking.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Locks",
            name: "unlock",
            summary: "Recover by releasing a stuck held file lock.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Intel",
            name: "context_pack",
            summary: "Assemble a focused code context bundle.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Intel",
            name: "code",
            summary: "Inspect code structure, symbols, and identifier uses.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Intel",
            name: "graph",
            summary: "Inspect imports, importers, cycles, callers, calls, and most-recently-modified files by mtime.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Intel",
            name: "search",
            summary: "Search project text with budgeted regular expressions.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Intel",
            name: "change_impact",
            summary: "Estimate impact for local changes.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Skills",
            name: "skill",
            summary: "Load named skill instructions and package support files.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Skills",
            name: "skill_manage",
            summary: "Create and manage local skills.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Planning",
            name: "plan_read",
            summary: "Read the shared plan document.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Planning",
            name: "plan_write",
            summary: "Replace the shared plan document.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Planning",
            name: "plan_edit",
            summary: "Patch the shared plan document.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Planning",
            name: "start_build",
            summary: "Start a build from the current plan.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Planning",
            name: "todo",
            summary: "Manage session todos and notes.",
            condition: Some("interactive sessions"),
        },
        BuiltinToolInventoryItem {
            family: "Session",
            name: "session_search",
            summary: "Search prior persisted sessions.",
            condition: Some("interactive sessions"),
        },
        BuiltinToolInventoryItem {
            family: "Session",
            name: "session_read",
            summary: "Read a prior persisted session.",
            condition: Some("interactive sessions"),
        },
        BuiltinToolInventoryItem {
            family: "Session",
            name: "session_lineage_search",
            summary: "Search the current session's compaction lineage.",
            condition: Some("interactive sessions"),
        },
        BuiltinToolInventoryItem {
            family: "Session",
            name: "artifact_read",
            summary: "Read an immutable session text artifact.",
            condition: Some("when the session has artifacts"),
        },
        BuiltinToolInventoryItem {
            family: "Session",
            name: "artifact_search",
            summary: "Search an immutable session text artifact.",
            condition: Some("when the session has artifacts"),
        },
        BuiltinToolInventoryItem {
            family: "Session",
            name: "delegation_payload_retrieve",
            summary: "Retrieve an elided delegation payload.",
            condition: Some("internal recovery"),
        },
        BuiltinToolInventoryItem {
            family: "Delegation",
            name: "task",
            summary: "Delegate work to configured subagents.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Delegation",
            name: "spawn",
            summary: "Spawn a subagent with an explicit role.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Delegation",
            name: "return",
            summary: "Return from a delegated agent.",
            condition: Some("delegated agents"),
        },
        BuiltinToolInventoryItem {
            family: "MCP",
            name: "mcp",
            summary: "Search, describe, and invoke MCP server tools.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "LSP",
            name: "lsp",
            summary: "Query language-server diagnostics and navigation.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Harnesses",
            name: "harness_list",
            summary: "List external coding harnesses.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Harnesses",
            name: "harness_invoke",
            summary: "Invoke an external coding harness.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Utility",
            name: "question",
            summary: "Ask the user a structured question.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Utility",
            name: "schedule",
            summary: "Schedule follow-up work.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Utility",
            name: "defer_to_orchestrator",
            summary: "Defer a decision to the orchestrator.",
            condition: None,
        },
        BuiltinToolInventoryItem {
            family: "Utility",
            name: "use_sealed_value",
            summary: "Use a granted sealed value by reference through a granted action.",
            condition: Some("Requires an Owner-issued sealed-value action grant."),
        },
        BuiltinToolInventoryItem {
            family: "Media",
            name: "inspect_audio",
            summary: "Inspect bounded audio metadata.",
            condition: Some("Requires FFprobe and typed session attachments."),
        },
        BuiltinToolInventoryItem {
            family: "Media",
            name: "inspect_video",
            summary: "Inspect video metadata and deterministic storyboards.",
            condition: Some(
                "Requires a compatible FFmpeg/FFprobe pair and typed session attachments.",
            ),
        },
        BuiltinToolInventoryItem {
            family: "Media",
            name: "extract_video_clip",
            summary: "Create a bounded normalized video clip.",
            condition: Some("Requires H.264/AAC encoders and typed session attachments."),
        },
        BuiltinToolInventoryItem {
            family: "Media",
            name: "extract_audio",
            summary: "Create a bounded PCM WAV derivative.",
            condition: Some("Requires FFmpeg PCM encoding and typed session attachments."),
        },
        BuiltinToolInventoryItem {
            family: "Media",
            name: "transcribe_audio",
            summary: "Transcribe an authorized audio source via an external transcription provider.",
            condition: Some(
                "Requires typed session attachments, configured transcription egress, and MediaEgress authorization.",
            ),
        },
        BuiltinToolInventoryItem {
            family: "Media",
            name: "read_image",
            summary: "Read, crop, and downscale an image into a typed media reference.",
            condition: Some("Requires typed session attachments and the image crate."),
        },
        BuiltinToolInventoryItem {
            family: "Media",
            name: "ask_image",
            summary: "Ask one bounded question about a single current-session image via a sidecar model.",
            condition: Some(
                "Routes through the sidecar egress policy; requires typed session attachments.",
            ),
        },
        #[cfg(feature = "extended")]
        BuiltinToolInventoryItem {
            family: "Image Generation",
            name: "list_image_generation_targets",
            summary: "List enabled image-generation targets with safe capability/health/cost projections.",
            condition: Some("Requires configured image-generation targets."),
        },
        #[cfg(feature = "extended")]
        BuiltinToolInventoryItem {
            family: "Image Generation",
            name: "generate_image",
            summary: "Generate one or more images from a text prompt.",
            condition: Some("Requires configured image-generation targets."),
        },
        #[cfg(feature = "extended")]
        BuiltinToolInventoryItem {
            family: "Image Generation",
            name: "get_image_generation_job",
            summary: "Get status and safe result metadata for an image-generation job.",
            condition: Some("Requires a session-owned job."),
        },
        #[cfg(feature = "extended")]
        BuiltinToolInventoryItem {
            family: "Image Generation",
            name: "cancel_image_generation_job",
            summary: "Request idempotent cancellation of an image-generation job.",
            condition: Some("Requires a session-controlled job."),
        },
    ]
}

fn extra_custom_tool_reserved_names() -> &'static [&'static str] {
    &[
        "webfetch",
        "websearch",
        "seed",
        "list-packages",
        "add-package",
        "artifact_read",
        "artifact_search",
        "delegation_payload_retrieve",
    ]
}

pub fn is_reserved_custom_tool_name(name: &str) -> bool {
    known_agent_tool_names().contains(&name) || extra_custom_tool_reserved_names().contains(&name)
}

fn validate_configured_custom_tools(
    config: &crate::daemon::session_worker::SessionConfigHandle,
) -> Result<()> {
    let cfg = config.extended();
    crate::config::extended::validate_web_custom_placeholders(&cfg.web)?;
    for name in cfg.tools.keys() {
        if is_reserved_custom_tool_name(name) {
            bail!(
                "custom tool `{name}` collides with a reserved cockpit tool name; choose a different custom tool name"
            );
        }
    }
    Ok(())
}

/// Builtin tools covered by registry invariants.
///
/// Keep this list next to the real builtin materializer so schema/description
/// coverage tracks the same static tools Cockpit can grant to agents. Configured
/// custom tools and web tool templates are intentionally excluded because their
/// author owns their wording at runtime.
#[cfg(test)]
pub(crate) fn invariant_builtin_tools() -> Vec<Arc<dyn crate::engine::tool::Tool>> {
    use crate::tools;
    vec![
        Arc::new(tools::read::ReadTool),
        Arc::new(tools::write::WriteTool),
        Arc::new(tools::unlock::UnlockTool),
        Arc::new(tools::edit::EditTool),
        Arc::new(tools::bash::BashTool::new()),
        Arc::new(tools::escalate::EscalateTool),
        Arc::new(tools::intel::ContextPackTool),
        Arc::new(tools::intel::CodeTool),
        Arc::new(tools::intel::GraphTool),
        Arc::new(tools::intel::SearchTool),
        Arc::new(tools::intel::ChangeImpactTool),
        Arc::new(tools::skill::SkillTool),
        Arc::new(tools::skill_manage::SkillManageTool),
        Arc::new(tools::question::QuestionTool),
        Arc::new(tools::defer::DeferTool),
        Arc::new(tools::schedule::ScheduleTool),
        Arc::new(tools::schedule::ForkScheduleTool::new(Arc::new(
            tools::schedule::ForkScheduleState::new("test".to_string()),
        ))),
        Arc::new(tools::schedule::NoteTool::new(
            Arc::new(tools::schedule::ForkScheduleState::new("test".to_string())),
            tokio::sync::mpsc::channel(1).0,
        )),
        Arc::new(tools::web::WebSearchTool),
        Arc::new(tools::web::WebFetchTool),
        Arc::new(tools::mcp_tool::McpTool),
        Arc::new(tools::lsp::LspTool),
        Arc::new(tools::return_tool::ReturnTool),
        Arc::new(tools::plan_doc::PlanReadTool),
        Arc::new(tools::plan_doc::PlanWriteTool),
        Arc::new(tools::plan_doc::PlanEditTool),
        Arc::new(tools::plan_doc::StartBuildTool),
        Arc::new(tools::session_search::SessionSearchTool),
        Arc::new(tools::session_read::SessionReadTool),
        Arc::new(tools::session_search::SessionLineageSearchTool),
        Arc::new(tools::todo::TodoTool),
        Arc::new(tools::artifact_read::ArtifactReadTool),
        Arc::new(tools::artifact_search::ArtifactSearchTool),
        Arc::new(tools::delegation_payload_retrieve::DelegationPayloadRetrieveTool),
        Arc::new(tools::spawn::SpawnTool::for_depth(0, 1)),
        Arc::new(tools::grep::GrepTool),
        Arc::new(tools::glob::GlobTool),
        Arc::new(tools::use_sealed_value::UseSealedValueTool::new()),
        Arc::new(tools::audio_video::InspectAudioTool),
        Arc::new(tools::audio_video::InspectVideoTool),
        Arc::new(tools::audio_video::ExtractVideoClipTool),
        Arc::new(tools::audio_video::ExtractAudioTool),
        Arc::new(tools::transcribe_audio::TranscribeAudioTool),
        Arc::new(tools::read_image::ReadImageTool),
        Arc::new(tools::ask_image::AskImageTool),
        #[cfg(feature = "extended")]
        Arc::new(crate::image_generation_agent_tools::ListImageGenerationTargetsTool),
        #[cfg(feature = "extended")]
        Arc::new(crate::image_generation_agent_tools::GenerateImageTool),
        #[cfg(feature = "extended")]
        Arc::new(crate::image_generation_agent_tools::GetImageGenerationJobTool),
        #[cfg(feature = "extended")]
        Arc::new(crate::image_generation_agent_tools::CancelImageGenerationJobTool),
        Arc::new(tools::docs::ListPackagesTool::new(
            tools::docs::DocsResolution::new(),
            "pkg".to_string(),
        )),
        Arc::new(tools::docs::AddPackageTool::new(
            tools::docs::DocsResolution::new(),
            None,
            None,
        )),
        Arc::new(tools::harness::HarnessListTool),
        Arc::new(tools::harness::HarnessInvokeTool),
        Arc::new(tools::task::TaskTool::with_subagents(&[
            "builder", "explore",
        ])),
    ]
}

fn materialize_tool_by_name(
    tb: ToolBox,
    name: &str,
    def: Option<&crate::agents::AgentDef>,
    args: &SpawnArgs,
) -> Result<ToolBox> {
    use crate::tools;
    let tb = match name {
        "read" => tb.with(Arc::new(tools::read::ReadTool)),
        "use_sealed_value" => tb.with(Arc::new(tools::use_sealed_value::UseSealedValueTool::new())),
        "inspect_audio" => tb.with(Arc::new(tools::audio_video::InspectAudioTool)),
        "inspect_video" => tb.with(Arc::new(tools::audio_video::InspectVideoTool)),
        "extract_video_clip" => tb.with(Arc::new(tools::audio_video::ExtractVideoClipTool)),
        "extract_audio" => tb.with(Arc::new(tools::audio_video::ExtractAudioTool)),
        "transcribe_audio" => tb.with(Arc::new(tools::transcribe_audio::TranscribeAudioTool)),
        "read_image" => tb.with(Arc::new(tools::read_image::ReadImageTool)),
        "ask_image" => tb.with(Arc::new(tools::ask_image::AskImageTool)),
        #[cfg(feature = "extended")]
        "list_image_generation_targets" => tb.with(Arc::new(
            crate::image_generation_agent_tools::ListImageGenerationTargetsTool,
        )),
        #[cfg(feature = "extended")]
        "generate_image" => tb.with(Arc::new(
            crate::image_generation_agent_tools::GenerateImageTool,
        )),
        #[cfg(feature = "extended")]
        "get_image_generation_job" => tb.with(Arc::new(
            crate::image_generation_agent_tools::GetImageGenerationJobTool,
        )),
        #[cfg(feature = "extended")]
        "cancel_image_generation_job" => tb.with(Arc::new(
            crate::image_generation_agent_tools::CancelImageGenerationJobTool,
        )),
        "bash" => tb.with(Arc::new(tools::bash::BashTool::new())),
        "escalate" => tb.with(Arc::new(tools::escalate::EscalateTool)),
        "write" => tb.with(Arc::new(tools::write::WriteTool)),
        "edit" => tb.with(Arc::new(tools::edit::EditTool)),
        "unlock" => tb.with(Arc::new(tools::unlock::UnlockTool)),
        "context_pack" => tb.with(Arc::new(tools::intel::ContextPackTool)),
        "code" => tb.with(Arc::new(tools::intel::CodeTool)),
        "graph" => tb.with(Arc::new(tools::intel::GraphTool)),
        "search" => tb.with(Arc::new(tools::intel::SearchTool)),
        "change_impact" => tb.with(Arc::new(tools::intel::ChangeImpactTool)),
        "skill" => tb.with(Arc::new(tools::skill::SkillTool)),
        "skill_manage" => tb.with(Arc::new(tools::skill_manage::SkillManageTool)),
        "question" => tb.with(Arc::new(tools::question::QuestionTool)),
        "schedule" => tb.with(Arc::new(tools::schedule::ScheduleTool)),
        "mcp" => tb.with(Arc::new(tools::mcp_tool::McpTool)),
        "webfetch" | "websearch" => tb.with(tools::web::materialize_web_tool(
            name,
            &args.config,
            &args.cwd,
        )?),
        "lsp" => tb.with(Arc::new(tools::lsp::LspTool)),
        "return" => tb.with(Arc::new(tools::return_tool::ReturnTool)),
        "plan_read" => tb.with(Arc::new(tools::plan_doc::PlanReadTool)),
        "plan_write" => tb.with(Arc::new(tools::plan_doc::PlanWriteTool)),
        "plan_edit" => tb.with(Arc::new(tools::plan_doc::PlanEditTool)),
        "start_build" => tb.with(Arc::new(tools::plan_doc::StartBuildTool)),
        "todo" => tb.with(Arc::new(tools::todo::TodoTool)),
        "defer_to_orchestrator" => tb.with(Arc::new(tools::defer::DeferTool)),
        "harness_list" => tb.with(Arc::new(tools::harness::HarnessListTool)),
        "harness_invoke" => tb.with(Arc::new(tools::harness::HarnessInvokeTool)),
        "session_search" => tb.with(Arc::new(tools::session_search::SessionSearchTool)),
        "session_read" => tb.with(Arc::new(tools::session_read::SessionReadTool)),
        "session_lineage_search" => {
            tb.with(Arc::new(tools::session_search::SessionLineageSearchTool))
        }
        "spawn" => tb.with(Arc::new(tools::spawn::SpawnTool::for_depth(
            args.swarm_depth,
            args.swarm_max_depth,
        ))),
        "task" => {
            let Some(def) = def else {
                bail!(
                    "tool `task` requires an agent definition to materialize reachable subagents"
                );
            };
            let subs = reachable_subagents(def, &args.config, &args.cwd);
            let sub_refs: Vec<&str> = subs.iter().map(String::as_str).collect();
            with_task_for_targets(tb, args, &sub_refs)
        }
        "grep" if def.is_some_and(|def| def.name == "docs-answerer") => {
            tb.with(Arc::new(tools::grep::GrepTool))
        }
        "glob" if def.is_some_and(|def| def.name == "docs-answerer") => {
            tb.with(Arc::new(tools::glob::GlobTool))
        }
        "grep" | "glob" => {
            bail!("tool `{name}` is docs-answerer-only and cannot be materialized for user agents")
        }
        other if known_agent_tool_names().contains(&other) => {
            bail!("tool `{other}` is admissible but has no materializer in this context")
        }
        other => bail!("unknown tool `{other}`"),
    };
    Ok(tb)
}

/// Append the per-session lines (harness identity + version + URLs +
/// optional user name + OS + session id) to the role-specific prompt
/// before handing it to [`Agent::system`]. Per GOALS §17g these stay
/// inside the cached system block — every field is stable for the
/// session's lifetime so prompt-cache hits aren't disturbed; the line
/// order is fixed so identical inputs produce a byte-identical block.
///
/// The layered config is loaded once here and reused for the user name.
fn mcp_resolver_for(
    args: &SpawnArgs,
    def: &crate::agents::AgentDef,
) -> std::sync::Arc<crate::mcp::resolver::EffectiveCatalogResolver> {
    crate::mcp::resolver::EffectiveCatalogResolver::for_agent(
        args.cwd.clone(),
        args.config.snapshot().generation,
        def,
    )
}

fn mcp_resolver_for_cwd(
    args: &SpawnArgs,
) -> std::sync::Arc<crate::mcp::resolver::EffectiveCatalogResolver> {
    crate::mcp::resolver::EffectiveCatalogResolver::with_config_generation(
        args.cwd.clone(),
        args.config.snapshot().generation,
    )
}

fn compose_system_prompt(role_prompt: &str, session_short_id: &str, cwd: &Path) -> String {
    let cfg = load_extended_config(cwd);
    compose_system_prompt_with(role_prompt, session_short_id, cwd, &cfg)
}

fn compose_system_prompt_for_model(role_prompt: &str, model: &Model, args: &SpawnArgs) -> String {
    let role_prompt = assistant_role_prompt(role_prompt, args.assistant_identity_prefix.as_deref());
    let model_prompt = args
        .model_system_prompt_snapshot
        .get(model.provider_id(), model.model_id_ref());
    if let Some(model_prompt) = model_prompt {
        let role_system = compose_system_prompt(&role_prompt, &args.session_short_id, &args.cwd);
        let mut out = String::with_capacity(model_prompt.len() + 2 + role_system.len());
        out.push_str(model_prompt);
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
        out.push_str(&role_system);
        out
    } else {
        compose_system_prompt(&role_prompt, &args.session_short_id, &args.cwd)
    }
}

fn assistant_role_prompt(role_prompt: &str, prefix: Option<&str>) -> String {
    let Some(prefix) = prefix.map(str::trim).filter(|s| !s.is_empty()) else {
        return role_prompt.to_string();
    };
    let mut out = String::with_capacity(prefix.len() + role_prompt.len() + 2);
    out.push_str(prefix);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push('\n');
    out.push_str(role_prompt);
    out
}

/// Pure assembler for the cached system block, given an already-resolved
/// [`ExtendedConfig`]. Split out from [`compose_system_prompt`] so the
/// formatting (line order, name trim/omit) is testable without depending
/// on which layered config the discovery walk happens to resolve on the
/// host machine. The line order is fixed for cache-stability (GOALS §17g).
///
/// Prompt-cache invariant (`prompt-caching-strategy.md`): every field here
/// is **stable for the session** — harness version, OS string, user name,
/// session id, MCP catalog. Project guidance deliberately rides in user-role
/// history, not this cached system block. There is **no** injected current
/// date/time, so the cached prefix never busts on a clock tick (e.g. a 24/7
/// session crossing midnight). Keep it that way: a volatile value added here
/// would re-warm the cache every time it changes.
fn compose_system_prompt_with(
    role_prompt: &str,
    session_short_id: &str,
    cwd: &Path,
    cfg: &crate::config::extended::ExtendedConfig,
) -> String {
    let os = cockpit_host::sysinfo::os_string();
    let mut out = String::with_capacity(role_prompt.len() + 192);
    out.push_str(role_prompt);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push('\n');
    out.push_str("Harness: cockpit ");
    out.push_str(env!("CARGO_PKG_VERSION"));
    out.push('\n');
    out.push_str("Website: https://flycockpit.dev | App: https://app.flycockpit.dev\n");
    if let Some(name) = cfg.name.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
        out.push_str("User: ");
        out.push_str(name);
        out.push('\n');
    }
    out.push_str("Operating system: ");
    out.push_str(&os);
    out.push('\n');
    if !session_short_id.is_empty() {
        out.push_str("Session: ");
        out.push_str(session_short_id);
        out.push('\n');
    }
    // Absolute working directory — the cwd anchor (GOALS §17g, §12). Stable
    // for the session, so the cached-prefix invariant holds; a parameterized-
    // cwd subagent (the `docs` answerer, §3a) receives its own spawn cwd here
    // and so shows the package dir, not the project root.
    out.push_str("Working directory: ");
    out.push_str(&cwd.display().to_string());
    out.push('\n');

    out
}

/// The full composed system prompt for the user-facing chat agent
/// (`Build`) at `cwd`: role prompt + harness/version/URL
/// lines + (optional) user-name line + OS line + (optional) session
/// line. Project guidance is injected as user-role history, not system text.
/// Used by the fresh-chat context
/// indicator to size the actual baseline sent to the model, in both
/// daemon (calibrated) and daemonless (raw cl100k) modes. Pass the empty
/// string for `session_short_id` when no session exists yet — it simply
/// omits the `Session:` line, matching what the engine sends.
pub fn default_chat_system_prompt(cwd: &Path, session_short_id: &str) -> String {
    compose_system_prompt(BUILD_PROMPT, session_short_id, cwd)
}

/// Per-category token sizing of the composed chat system prompt, for the
/// `/context` usage overlay. Splits the single composed block the engine
/// sends into the three buckets that actually make it up, so the overlay
/// can color them distinctly rather than reporting one opaque "system"
/// number. Counts are cl100k_base (`crate::tokens::count`) — the same
/// fallback the chrome's live context indicator uses pre-flight.
///
/// - `base_prompt`: the role/base system prompt (the `Build` agent's
///   `build.md`), the fixed instruction surface.
/// - `system_block`: the appended cached identity lines (harness +
///   version + URLs + optional user name + OS + optional session id),
///   GOALS §17g.
/// - `guidance`: the injected project-guidance / memory file body
///   (`AGENTS.md` / `project guidance` / …), or 0 when none was found.
///
/// Derived from the same guidance lookup and system assembly the engine uses,
/// but guidance is reported as the separate user-role prelude it will occupy on
/// the wire.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SystemPromptBreakdown {
    pub model_instructions: u64,
    pub base_prompt: u64,
    pub system_block: u64,
    pub guidance: u64,
}

/// Compute the [`SystemPromptBreakdown`] for the user-facing chat agent
/// (`Build`) at `cwd`. `session_short_id` is empty when no session id is
/// resolved yet (matching what the engine sends on a fresh chat).
pub fn chat_system_prompt_breakdown(
    cwd: &Path,
    session_short_id: &str,
    model_instructions: Option<&str>,
) -> SystemPromptBreakdown {
    let cfg = load_extended_config(cwd);
    // The full composed system prompt, then the same prompt without the role
    // body: the difference is the cached identity block. Guidance is counted
    // separately because it is sent as user-role history.
    let model_instructions = model_instructions
        .map(|prompt| crate::tokens::count(prompt) as u64)
        .unwrap_or(0);
    let base_prompt = crate::tokens::count(BUILD_PROMPT) as u64;
    let guidance = find_agent_guidance(cwd, &cfg.agent_guidance_files)
        .map(|(_, body)| crate::tokens::count(&body) as u64)
        .unwrap_or(0);
    let full = crate::tokens::count(&compose_system_prompt_with(
        BUILD_PROMPT,
        session_short_id,
        cwd,
        &cfg,
    )) as u64;
    let system_block = full.saturating_sub(base_prompt);
    SystemPromptBreakdown {
        model_instructions,
        base_prompt,
        system_block,
        guidance,
    }
}

/// Locate the first existing project-guidance file by name, searching
/// `cwd` then its ancestors up to (and including) the git worktree root
/// when there is one — otherwise stop at the filesystem root. Returns
/// the absolute path + file body.
pub fn load_agent_guidance(cwd: &Path) -> Option<(std::path::PathBuf, String)> {
    let cfg = load_extended_config(cwd);
    find_agent_guidance(cwd, &cfg.agent_guidance_files)
}

/// Load the effective layered `config.json` that applies to `cwd`.
/// [`compose_system_prompt`] loads this once and reads both the user name and
/// the guidance-file list from it, so config is never loaded twice per spawn.
fn load_extended_config(cwd: &Path) -> crate::config::extended::ExtendedConfig {
    crate::config::extended::load_for_cwd(cwd)
}

/// Inner search used by [`load_agent_guidance`]. Walks `cwd` and its
/// ancestors (stopping at the git worktree root) and returns the first
/// existing file whose basename matches an entry in `names`, scanning
/// `names` in order at each directory level. Exposed for tests so they
/// can pin the name list without touching layered config.
fn find_agent_guidance(cwd: &Path, names: &[String]) -> Option<(std::path::PathBuf, String)> {
    if names.is_empty() {
        return None;
    }
    let stop_at = crate::git::find_worktree_root(cwd);
    let mut dir: Option<&Path> = Some(cwd);
    while let Some(d) = dir {
        for name in names {
            let candidate = d.join(name);
            if candidate.is_file()
                && let Ok(body) = std::fs::read_to_string(&candidate)
            {
                return Some((candidate, body));
            }
        }
        if let Some(root) = &stop_at
            && d == root.as_path()
        {
            break;
        }
        dir = d.parent();
    }
    None
}

/// Load user-defined custom-bash tools from the effective layered config and
/// append them to `tb`. Web provider config is the only source for the
/// built-in web tools; the `tools` map is only user-defined tools.
/// Disabled/discoverable rows and empty commands are skipped because
/// non-direct named grants are materialized by the tiered grant loop.
fn with_custom_tools(
    mut tb: ToolBox,
    config: &crate::daemon::session_worker::SessionConfigHandle,
    cwd: &Path,
    non_direct_tools: &std::collections::BTreeSet<String>,
) -> ToolBox {
    let cfg = config.extended();

    if cfg.web.provider != crate::config::extended::WebProvider::Custom {
        if !non_direct_tools.contains(crate::tools::custom::WEBFETCH) {
            tb = tb.with(Arc::new(crate::tools::web::WebFetchTool));
        }
        if !non_direct_tools.contains(crate::tools::custom::WEBSEARCH) {
            tb = tb.with(Arc::new(crate::tools::web::WebSearchTool));
        }
    } else {
        for (name, command) in [
            (
                crate::tools::custom::WEBFETCH,
                cfg.web.custom.fetch_command.as_deref(),
            ),
            (
                crate::tools::custom::WEBSEARCH,
                cfg.web.custom.search_command.as_deref(),
            ),
        ] {
            if non_direct_tools.contains(name) {
                continue;
            }
            let Some(command) = command.map(str::trim).filter(|command| !command.is_empty()) else {
                continue;
            };
            let tpl = crate::config::extended::ToolCommandTemplate {
                enabled: true,
                command: command.to_string(),
                description: None,
            };
            tb = tb.with(Arc::new(CustomBashTool::from_template_with_provenance(
                name,
                &tpl,
                ToolTemplateProvenance::Configured {
                    source: format!(
                        "web.custom command in effective config for {}",
                        cwd.display()
                    ),
                },
            )));
        }
    }

    for (name, tpl) in cfg.tools.iter() {
        if non_direct_tools.contains(name) {
            continue;
        }
        if !tpl.enabled || tpl.command.trim().is_empty() {
            continue;
        }
        tb = tb.with(Arc::new(CustomBashTool::from_template_with_provenance(
            name,
            tpl,
            ToolTemplateProvenance::Configured {
                source: format!("effective config for {}", cwd.display()),
            },
        )));
    }
    tb
}

fn non_direct_tier_names(def: &crate::agents::AgentDef) -> std::collections::BTreeSet<String> {
    let mut names: std::collections::BTreeSet<String> = def
        .tool_tiers
        .iter()
        .filter(|(_name, tier)| **tier != crate::agents::ToolTier::Enabled)
        .map(|(name, _tier)| name.clone())
        .collect();
    names.extend(
        default_discoverable_tools_for(&def.name)
            .iter()
            .map(|name| (*name).to_string()),
    );
    names
}

pub(crate) fn default_discoverable_tools_for(name: &str) -> &'static [&'static str] {
    match name {
        "Build" | "builder" | "Plan" => &[
            "graph",
            "change_impact",
            "harness_list",
            "harness_invoke",
            "session_search",
            "session_read",
            "session_lineage_search",
            "lsp",
        ],
        "Careful" => &[
            "context_pack",
            "code",
            "graph",
            "change_impact",
            "lsp",
            "skill",
            "harness_list",
            "harness_invoke",
            "session_search",
            "session_read",
            "session_lineage_search",
            "todo",
            "webfetch",
            "websearch",
        ],
        "Multireview" => &[
            "harness_list",
            "harness_invoke",
            "session_search",
            "session_read",
            "session_lineage_search",
            "lsp",
        ],
        _ => &[],
    }
}

pub(crate) fn default_disabled_tools_for(name: &str) -> &'static [&'static str] {
    match name {
        "Build" | "builder" | "Plan" | "Careful" | "bee" | "scout" | "explore" | "Multireview" => {
            &["skill_manage"]
        }
        _ => &[],
    }
}

fn default_assistant_discoverable_tools() -> &'static [&'static str] {
    &["session_search", "session_read", "session_lineage_search"]
}

fn effective_tool_tier(
    def: &crate::agents::AgentDef,
    tool: &str,
    is_assistant: bool,
) -> crate::agents::ToolTier {
    if let Some(tier) = def.tool_tiers.get(tool) {
        return *tier;
    }
    // Media tiers respect the discoverable-mcp reachability invariant
    // (`validate_discoverable_mcp_reachable`): a Discoverable tool is only
    // reachable on an agent that also grants `mcp`. `Careful` keeps a small
    // direct surface and reaches broader Build capabilities through `mcp`, so
    // its media tools are Discoverable (mcp-reachable), not direct. The read
    // workers `scout`/`bee` hold no `mcp` grant and keep a fixed direct
    // surface (their embedded factories carry no media), so media tiers to
    // Disabled for them rather than to an unreachable Discoverable entry.
    if matches!(tool, "inspect_audio" | "inspect_video") {
        return match def.name.as_str() {
            "Build" | "Plan" | "explore" => crate::agents::ToolTier::Enabled,
            "Careful" | "builder" | "deepthink" | "Multireview" => {
                crate::agents::ToolTier::Discoverable
            }
            _ => crate::agents::ToolTier::Disabled,
        };
    }
    if matches!(
        tool,
        "extract_video_clip" | "extract_audio" | "transcribe_audio"
    ) {
        return match def.name.as_str() {
            "Build" => crate::agents::ToolTier::Enabled,
            "Careful" | "builder" => crate::agents::ToolTier::Discoverable,
            _ => crate::agents::ToolTier::Disabled,
        };
    }
    // Image-generation discovery is read-only and safe-projection only, so it
    // rides on the same agent classes as `read_image` (every tier that gets
    // read_image also gets discovery: primaries/explorer direct, the
    // narrow-surface workers mcp-reachable Discoverable). It never grants
    // generation authority.
    #[cfg(feature = "extended")]
    if tool == "list_image_generation_targets" {
        return match def.name.as_str() {
            "Build" | "Plan" | "explore" => crate::agents::ToolTier::Enabled,
            "Careful" | "builder" | "deepthink" | "Multireview" => {
                crate::agents::ToolTier::Discoverable
            }
            _ => crate::agents::ToolTier::Disabled,
        };
    }
    // The productive / control image-generation tools (`generate_image`, plus the
    // job status/cancel that operate only on jobs this session produced) mirror
    // the `extract_*` set: the write-capable `Build` primary direct, the
    // narrow-surface coding workers `Careful`/`builder` mcp-reachable
    // Discoverable, and Disabled everywhere else (no read-only/narrow subagent
    // gets generation or job control). The whole surface stays fail-closed until
    // the daemon adapter map lands.
    #[cfg(feature = "extended")]
    if matches!(
        tool,
        "generate_image" | "get_image_generation_job" | "cancel_image_generation_job"
    ) {
        return match def.name.as_str() {
            "Build" => crate::agents::ToolTier::Enabled,
            "Careful" | "builder" => crate::agents::ToolTier::Discoverable,
            _ => crate::agents::ToolTier::Disabled,
        };
    }
    // `ask_image` is attached to the same agent classes as `read_image`
    // (default: every tier that gets read_image also gets ask_image), so vision
    // questions go through the sidecar egress policy rather than the primary.
    if matches!(tool, "read_image" | "ask_image") {
        return match def.name.as_str() {
            "Build" | "Plan" | "explore" => crate::agents::ToolTier::Enabled,
            "Careful" | "builder" | "deepthink" | "Multireview" => {
                crate::agents::ToolTier::Discoverable
            }
            _ => crate::agents::ToolTier::Disabled,
        };
    }
    if is_assistant && default_assistant_discoverable_tools().contains(&tool) {
        return crate::agents::ToolTier::Discoverable;
    }
    if default_disabled_tools_for(&def.name).contains(&tool) {
        return crate::agents::ToolTier::Disabled;
    }
    if default_discoverable_tools_for(&def.name).contains(&tool) {
        return crate::agents::ToolTier::Discoverable;
    }
    crate::agents::ToolTier::Enabled
}

fn with_audio_video_tools(
    mut tb: ToolBox,
    def: &crate::agents::AgentDef,
    args: &SpawnArgs,
) -> Result<ToolBox> {
    for name in [
        "inspect_audio",
        "inspect_video",
        "extract_video_clip",
        "extract_audio",
        "transcribe_audio",
    ] {
        tb = match effective_tool_tier(def, name, false) {
            crate::agents::ToolTier::Enabled => add_tool_by_name(tb, name, def, args)?,
            crate::agents::ToolTier::Discoverable => {
                add_discoverable_tool_by_name(tb, name, def, args)?
            }
            crate::agents::ToolTier::Disabled => tb,
        };
    }
    Ok(tb)
}

fn with_read_image_tools(
    mut tb: ToolBox,
    def: &crate::agents::AgentDef,
    args: &SpawnArgs,
) -> Result<ToolBox> {
    tb = match effective_tool_tier(def, "read_image", false) {
        crate::agents::ToolTier::Enabled => add_tool_by_name(tb, "read_image", def, args)?,
        crate::agents::ToolTier::Discoverable => {
            add_discoverable_tool_by_name(tb, "read_image", def, args)?
        }
        crate::agents::ToolTier::Disabled => tb,
    };
    Ok(tb)
}

fn with_ask_image_tools(
    mut tb: ToolBox,
    def: &crate::agents::AgentDef,
    args: &SpawnArgs,
) -> Result<ToolBox> {
    tb = match effective_tool_tier(def, "ask_image", false) {
        crate::agents::ToolTier::Enabled => add_tool_by_name(tb, "ask_image", def, args)?,
        crate::agents::ToolTier::Discoverable => {
            add_discoverable_tool_by_name(tb, "ask_image", def, args)?
        }
        crate::agents::ToolTier::Disabled => tb,
    };
    Ok(tb)
}

#[cfg(feature = "extended")]
fn with_image_generation_tools(
    mut tb: ToolBox,
    def: &crate::agents::AgentDef,
    args: &SpawnArgs,
) -> Result<ToolBox> {
    for name in [
        "list_image_generation_targets",
        "generate_image",
        "get_image_generation_job",
        "cancel_image_generation_job",
    ] {
        tb = match effective_tool_tier(def, name, false) {
            crate::agents::ToolTier::Enabled => add_tool_by_name(tb, name, def, args)?,
            crate::agents::ToolTier::Discoverable => {
                add_discoverable_tool_by_name(tb, name, def, args)?
            }
            crate::agents::ToolTier::Disabled => tb,
        };
    }
    Ok(tb)
}

fn add_discoverable_tool_by_name(
    tb: ToolBox,
    name: &str,
    def: &crate::agents::AgentDef,
    args: &SpawnArgs,
) -> Result<ToolBox> {
    let scratch = materialize_tool_by_name(ToolBox::new(), name, Some(def), args)?;
    let Some(tool) = scratch.get_cloned(name) else {
        return Ok(tb);
    };
    Ok(tb.with_discoverable_mcp(tool))
}

fn validate_discoverable_mcp_reachable(def: &crate::agents::AgentDef, tb: &ToolBox) -> Result<()> {
    let discoverable = tb.discoverable_mcp_tool_names();
    if discoverable.is_empty() || tb.names().contains(&"mcp") {
        return Ok(());
    }

    bail!(
        "agent `{}` has discoverable MCP tools [{}] but does not grant `mcp`, so they are unreachable; grant `mcp` or tier them `enabled`",
        def.name,
        discoverable.join(", ")
    );
}

/// Build an agent by name. Resolution order (overlay model, prompt
/// `user-definable-agents.md`):
///   1. An on-disk override / custom agent ([`crate::agents::resolve`])
///      — the user's edited or new definition wins, and its
///      prompt/tools/model/temperature flow into the constructed agent.
///   2. The embedded factory function for a built-in (no override) —
///      unchanged byte-for-byte so the cached system prefix and exact
///      tool surface are preserved (prompt-cache discipline).
///
/// Returns `Err` for unknown names so the `task` tool can surface
/// "unknown agent" loudly rather than silently spawning the wrong one.
pub fn load(name: &str, args: &SpawnArgs) -> Result<Agent> {
    load_with_tool_surface_override(name, args, None)
}

pub fn load_with_tool_surface_override(
    name: &str,
    args: &SpawnArgs,
    tool_surface_override: Option<&crate::agents::ToolSurfaceSelection>,
) -> Result<Agent> {
    validate_configured_custom_tools(&args.config)?;

    // The docs pipeline stages are routed by the driver and never reach
    // here through a name; guard them before any disk resolution so a
    // stray `agents/docs.md` can't hijack the pipeline.
    if matches!(name, "docs" | "docs-resolver" | "docs-answerer") {
        bail!(
            "`{name}` is a pipeline stage routed by the driver; load() should be unreachable for it"
        );
    }
    if name == "computer" {
        return computer(args);
    }

    if let Some(mut def) = local_definition_for_spawn(name, args)? {
        return load_resolved_def(name, args, tool_surface_override, &mut def);
    }

    // Overlay: an on-disk override (edited built-in) or a custom agent
    // takes precedence over the embedded factory. A malformed override
    // fails loudly here (naming its source) rather than silently falling
    // back to the embedded default.
    let Some(mut def) = crate::agents::resolve(&args.cwd, name)? else {
        // Not a built-in and no file on disk: unknown agent.
        bail!("unknown agent `{name}`");
    };
    load_resolved_def(name, args, tool_surface_override, &mut def)
}

/// Rebuild a running foreground agent from the exact definition snapshot that
/// originally constructed it. Config-driven tool/model material is refreshed
/// through `args`, but edits to the definition itself affect only agents built
/// after the edit (new children or a newly started root session).
pub(crate) fn rebuild_from_pinned_definition(agent: &Agent, args: &SpawnArgs) -> Result<Agent> {
    let definition = agent.definition.as_ref().ok_or_else(|| {
        anyhow::anyhow!("running agent `{}` has no pinned definition", agent.name)
    })?;
    let mut definition = (**definition).clone();
    let mut rebuilt = load_resolved_def(&agent.name, args, None, &mut definition)?;
    // A foreground child may already carry the parent's no-widening
    // intersection. Rebuilding from its governing definition must not restore
    // grants removed at admission.
    rebuilt.posture = agent.posture.clone();
    Ok(rebuilt)
}

pub async fn load_with_assistant_db_and_tool_surface_override(
    name: &str,
    args: &SpawnArgs,
    db: &crate::db::Db,
    tool_surface_override: Option<&crate::agents::ToolSurfaceSelection>,
) -> Result<Agent> {
    validate_configured_custom_tools(&args.config)?;
    if matches!(name, "docs" | "docs-resolver" | "docs-answerer") {
        bail!(
            "`{name}` is a pipeline stage routed by the driver; load() should be unreachable for it"
        );
    }
    if name == "computer" {
        return computer(args);
    }

    if let Some(mut def) = local_definition_for_spawn(name, args)? {
        return load_resolved_def(name, args, tool_surface_override, &mut def);
    }
    let def = crate::agents::resolve_with_assistant_db(&args.cwd, name, db).await?;
    let Some(mut def) = def else {
        bail!("unknown agent `{name}");
    };
    load_resolved_def(name, args, tool_surface_override, &mut def)
}

/// Select a daemon-local definition only through an authenticated UUID grant
/// (or the authenticated private-assistant root session).  This returns the
/// captured definition snapshot itself, preventing every construction path
/// from re-reading a workspace file with the same display name.
fn local_definition_for_spawn(
    name: &str,
    args: &SpawnArgs,
) -> Result<Option<crate::agents::AgentDef>> {
    if let Some(parent) = &args.parent_vnext_grant {
        if let Some(definition) = args
            .vnext_local_installation_resolver
            .package_definition_for_parent_launch_target(parent, name)
        {
            return Ok(Some(definition));
        }
        return args
            .vnext_local_installation_resolver
            .definition_for_parent_launch_target(parent, name)
            .map(|resolved| resolved.map(|(_, definition)| definition));
    }
    if args.assistant_identity_prefix.is_some() && !args.delegated {
        return args
            .vnext_local_installation_resolver
            .root_definition_for_launch_target(name);
    }
    if !args.delegated {
        return args
            .vnext_local_installation_resolver
            .prepared_root_definition_for_launch_target(name);
    }
    Ok(None)
}

fn load_resolved_def(
    name: &str,
    args: &SpawnArgs,
    tool_surface_override: Option<&crate::agents::ToolSurfaceSelection>,
    def: &mut crate::agents::AgentDef,
) -> Result<Agent> {
    if let Some(selection) = tool_surface_override {
        crate::agents::apply_tool_surface_override(def, selection)?;
    }
    let mut agent = agent_from_def(def, args)?;

    // Per-delegation tool grants (prompt `parent-granted-tools.md`): append the
    // parent's granted tools onto the just-built base surface, for this run
    // only. The grant was already validated against the role invariants in the
    // driver before the spawn; this only materializes the named tools. A child
    // is a fresh context, so its tool set (base + grants) is fixed here at spawn
    // — the cache-safety rule holds per child-run, and grants can't persist or
    // leak because each spawn passes a fresh `SpawnArgs.granted_tools`.
    if !args.granted_tools.is_empty() && name != "deepthink" {
        if def.vnext.is_some() {
            bail!("vNext definitions cannot receive legacy granted_tools authority");
        }
        let is_assistant = def.vnext.as_ref().map_or(
            args.assistant_identity_prefix.is_some()
                && crate::agents::embedded_default(&def.name).is_none(),
            |definition| definition.execution_kind == crate::agents::ExecutionKind::Assistant,
        );
        for grant in &args.granted_tools {
            if effective_tool_tier(def, grant, is_assistant) == crate::agents::ToolTier::Disabled {
                bail!(
                    "delegation to `{name}` may not grant tool `{grant}` because `{name}` tiers it as `disabled`"
                );
            }
        }
        agent.tools = apply_grants(agent.tools, &args.granted_tools, args)?;
    }
    agent.params = params_with_direct_computer(args, &agent.model);
    Ok(agent)
}

pub fn default_build(args: &SpawnArgs) -> Agent {
    let def = crate::agents::embedded_default("Build").expect("Build has an embedded default");
    agent_from_def(&def, args).expect("Build embedded default constructs")
}

/// Append the parent-granted tools onto a built agent's base toolbox (prompt
/// `parent-granted-tools.md`). Only non-structural, non-delegation tools are
/// grantable (the delegation tools are rejected up front by
/// [`crate::agents::invariants::validate_grant`], so they never reach here),
/// which is why no `AgentDef`/subagent wiring is needed. A name already present
/// on the box (the parent granted a tool the child already holds) is a no-op
/// re-insert of the same instance — harmless and idempotent. An unrecognized
/// name is skipped: it was either rejected at validation or is a config-driven
/// custom-bash tool that isn't granted this way.
fn apply_grants(mut tb: ToolBox, grants: &[String], args: &SpawnArgs) -> Result<ToolBox> {
    for name in grants {
        tb = materialize_tool_by_name(tb, name, None, args)?;
    }
    Ok(tb)
}

/// True if `name` denotes an agent that runs *noninteractively* when
/// delegated to via `task` — the primary dispatches it like a tool call
/// (synchronously) rather than handing the primary conversation off. The
/// driver uses this to route `task(agent=…, …)` correctly.
///
/// `builder` (the writer handoff, GOALS §3a/§3b) is the interactive handoff
/// subagent: it takes over the conversation and talks to the user directly.
/// Everything else delegated via `task` — `explore`, the `docs`
/// pipeline (leaf-terminated, GOALS §3a), and every user-authored custom
/// subagent — runs noninteractively and reports one leaf result up. Defined
/// as the complement of the interactive set so custom agents inherit the
/// safe default without a registry. A caller may still override per-call via
/// `task(mode=…)`; this is only the default.
pub fn is_noninteractive(name: &str) -> bool {
    name != "builder"
}

/// The `docs` pipeline stage names. They run as a fixed two-stage,
/// leaf-terminated internal flow (GOALS §3a) routed by the driver — never a
/// general delegation — and are **excluded** from the re-queryable-subagent
/// feature (GOALS §3c): their transcript is never persisted as a handle.
pub(crate) fn is_docs_pipeline(name: &str) -> bool {
    matches!(name, "docs" | "docs-resolver" | "docs-answerer")
}

fn is_internal_agent_def_name(name: &str) -> bool {
    matches!(name, "computer" | "docs-resolver" | "docs-answerer")
}

fn internal_agent_def_uses_custom_tools(name: &str) -> bool {
    name == "docs-resolver"
}

/// True when a delegated subagent named `name` is **follow-up eligible** — its
/// transcript may be persisted as a re-query handle and a later
/// `task(resume_handle=…)` may resume it (GOALS §3c). This is the *superset* of
/// [`is_read_only_noninteractive`]: it admits write-capable subagents
/// (`builder`) and interactive handoff subagents (`builder`) in
/// addition to read-only leaves (`explore`) and custom subagents, so a
/// finished writer can be re-queried without re-running from scratch
/// (implementation note). The **only** structural
/// exclusion is the `docs` pipeline (a fixed leaf flow whose answer is the
/// payload — never persisted). A read-only follow-up is naturally read-only;
/// a write-capable follow-up re-acquires its locks hash-matched on resume.
pub fn is_followup_eligible(name: &str) -> bool {
    !is_docs_pipeline(name)
}

/// True when `agent` is a **read-only noninteractive** subagent — the scope
/// of the re-queryable-subagent + seeding feature (GOALS §3c). Derived
/// generically, not from a hardcoded name list:
///
/// - it runs noninteractively ([`is_noninteractive`]),
/// - it is not a `docs` pipeline stage (excluded structurally),
/// - it holds **none** of the single-writer lock/write tools
///   ([`crate::agents::invariants::LOCK_WRITE_TOOLS`]) — i.e. it cannot
///   mutate the tree, so re-running it is side-effect-free, and
/// - it is a leaf — it holds no `task` (it delegates to no one; re-querying
///   must not grant a subagent new delegation powers, leaf-termination,
///   GOALS §3c).
///
/// Today this is `explore` (and any custom read-only leaf subagent); a future
/// read-only noninteractive leaf subagent qualifies automatically. A primary
/// (`Build`/`Plan`) is excluded by the leaf check — it holds `task` — and is
/// never delegated to via `task` anyway.
pub fn is_read_only_noninteractive(agent: &Agent) -> bool {
    if !is_noninteractive(&agent.name) || is_docs_pipeline(&agent.name) {
        return false;
    }
    !is_write_capable(agent) && !is_delegating(agent)
}

/// True when `agent` holds any of the single-writer lock/write tools
/// ([`crate::agents::invariants::LOCK_WRITE_TOOLS`]) — i.e. it can mutate the
/// tree. Structural (derived from the held tool surface), not name-bound, so a
/// custom write-capable subagent qualifies automatically. A write-capable
/// follow-up (implementation note) uses this to decide
/// whether to re-acquire file locks hash-matched on resume; a read-only
/// subagent has nothing to resume writing.
pub fn is_write_capable(agent: &Agent) -> bool {
    let names = agent.tools.names();
    crate::agents::invariants::LOCK_WRITE_TOOLS
        .iter()
        .any(|w| names.contains(w))
}

/// True when `agent` holds a delegation tool (`task`) — it is not a leaf. Used
/// to keep the read-only-leaf scope tight.
fn is_delegating(agent: &Agent) -> bool {
    agent.tools.names().contains(&"task")
}

/// Side-effect-free resolution of the concrete model a delegated child named
/// `name` would run under, using the SAME precedence the agent build applies
/// (`model_override` → agent-file frontmatter / caller selector → session
/// model), from the config generation pinned on `args`.
///
/// This lets the driver gate a child-execution capability (follow-up
/// eligibility, handoff-tag expansion) on the child's OWN resolved posture
/// before the child agent is built, without re-reading the parent frame. It
/// resolves nothing but a model — it creates no task/child record, spawns no
/// agent, and mutates no lifecycle state.
pub(crate) fn resolve_child_model(name: &str, args: &SpawnArgs) -> Result<Arc<Model>> {
    if let Some(model) = &args.model_override {
        return Ok(model.clone());
    }
    let def = resolve_child_def(name, args)?;
    resolve_agent_model(&def, args)
}

/// Resolve the SAME [`crate::agents::AgentDef`] the dispatch will build the child
/// from. The `docs` pipeline stages and `computer` are internal-only defs that
/// ALWAYS build the EMBEDDED def — so any on-disk `docs-resolver.md` /
/// `docs-answerer.md` / `computer.md` override is intentionally ignored here,
/// keeping the resolved handoff/failover posture identical to the dispatched
/// stage. Every other agent resolves through the normal on-disk/embedded path.
fn resolve_child_def(name: &str, args: &SpawnArgs) -> Result<crate::agents::AgentDef> {
    if is_internal_agent_def_name(name) {
        return crate::agents::embedded_internal_default(name)
            .ok_or_else(|| anyhow::anyhow!("unknown internal agent `{name}`"));
    }
    if let Some(definition) = local_definition_for_spawn(name, args)? {
        return Ok(definition);
    }
    match crate::agents::resolve(&args.cwd, name)? {
        Some(def) => Ok(def),
        None => crate::agents::embedded_internal_default(name)
            .ok_or_else(|| anyhow::anyhow!("unknown agent `{name}`")),
    }
}

/// Like [`resolve_child_def`] but resolving through the SAME workspace +
/// assistant-DB path the original build used
/// ([`load_with_assistant_db_and_tool_surface_override`]), so an
/// assistant-DB-backed agent's def is found (not just on-disk/embedded ones).
async fn resolve_child_def_with_db(
    name: &str,
    cwd: &Path,
    db: &crate::db::Db,
) -> Result<crate::agents::AgentDef> {
    if is_internal_agent_def_name(name) {
        return crate::agents::embedded_internal_default(name)
            .ok_or_else(|| anyhow::anyhow!("unknown internal agent `{name}`"));
    }
    match crate::agents::resolve_with_assistant_db(cwd, name, db).await? {
        Some(def) => Ok(def),
        None => crate::agents::embedded_internal_default(name)
            .ok_or_else(|| anyhow::anyhow!("unknown agent `{name}`")),
    }
}

/// Re-render an already-built delegated child's model-dependent surface for a
/// FAILOVER/BACKUP candidate `candidate_model`, recomposing the agent's
/// system prompt for the candidate model. Per issue #75 the posture (tool
/// steering, capability grants, context policy) comes from the agent's def
/// and is model-independent, so only the composed `system` and `model`
/// plus the candidate-selected role body change; the toolbox, grants, and
/// steering are preserved.
///
/// Returns `Ok(None)` ONLY when the candidate is the SAME model as the
/// current agent (the primary attempt — no re-render needed). Any different
/// MODEL re-renders, because the composed `system` is model-specific (it
/// prepends the candidate model's own system prompt): a same-def,
/// different-model backup must NOT reuse the primary model's composed system.
///
/// The governing definition is the running agent's pinned snapshot. Older test
/// and recovery agents without that snapshot re-resolve through the same
/// workspace + assistant database path as their original construction. The
/// candidate then selects its own per-model prompt override without changing
/// the definition's posture or grants.
pub(crate) async fn reposture_agent_for_candidate(
    agent: &Agent,
    candidate_model: &Arc<Model>,
    session: &crate::session::Session,
    cwd: &Path,
    db: &crate::db::Db,
) -> Result<Option<Agent>> {
    let same_model = agent.model.provider_id() == candidate_model.provider_id()
        && agent.model.model_id_ref() == candidate_model.model_id_ref();
    if same_model {
        return Ok(None);
    }
    let definition = match &agent.definition {
        Some(definition) => (**definition).clone(),
        None => resolve_child_def_with_db(&agent.name, cwd, db).await?,
    };
    if let Some(warning) = definition.model_override_warning(
        candidate_model.provider_id(),
        candidate_model.model_id_ref(),
    ) {
        tracing::warn!(agent = %agent.name, provider = %candidate_model.provider_id(), model = %candidate_model.model_id_ref(), %warning, "failover model is outside agent definition suggestions");
    }
    let role = definition
        .resolved_prompt_for_model(
            candidate_model.provider_id(),
            candidate_model.model_id_ref(),
        )
        .to_string();
    // Recompose the system for the ACTUAL candidate model (its own
    // model-specific system prompt), applying the SAME assistant identity
    // prefix the initial build used, so the repostured system is byte-identical
    // to a fresh build for this candidate model.
    let system = compose_reposture_system(
        &role,
        candidate_model,
        agent.assistant_identity_prefix.as_deref(),
        session,
        cwd,
    );
    let mut reposed = agent.clone();
    reposed.role_prompt = role;
    reposed.system = system;
    reposed.model = candidate_model.clone();
    Ok(Some(reposed))
}

/// Recompose the cached system block for a failover candidate's posture. Mirrors
/// [`compose_system_prompt_for_model`] exactly, using the pieces available at
/// dispatch time (the session snapshot + short id + cwd) plus the retained
/// `assistant_identity_prefix`, so an assistant-owned session's failover keeps
/// its SOUL/USER identity/instructions.
fn compose_reposture_system(
    role: &str,
    model: &Model,
    assistant_identity_prefix: Option<&str>,
    session: &crate::session::Session,
    cwd: &Path,
) -> String {
    let snapshot = session.model_system_prompt_snapshot();
    let role = assistant_role_prompt(role, assistant_identity_prefix);
    let short_id = session.short_id();
    let role_system = compose_system_prompt(&role, &short_id, cwd);
    match snapshot.get(model.provider_id(), model.model_id_ref()) {
        Some(model_prompt) => {
            let mut out = String::with_capacity(model_prompt.len() + 2 + role_system.len());
            out.push_str(model_prompt);
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out.push('\n');
            out.push_str(&role_system);
            out
        }
        None => role_system,
    }
}

/// Immutable, side-effect-free description of the execution surface a delegated
/// child would present if dispatched now, resolved from the child's OWN
/// selected provider/model at a single config generation.
///
/// It is the ONLY contract a caller may use to admit a child for concurrent
/// execution, and it is bound (by [`Self::config_generation`]) to the attempt
/// that consumes it: if the generation changes before the attempt starts, the
/// caller must discard this surface and re-resolve from the generation that
/// actually starts, rather than admitting a child under stale posture or
/// capabilities. Constructing one is a pure resolution/preflight operation — it
/// creates no task/child record, spawns no agent, pregrants no write scope,
/// requests no approval, and mutates no task lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedChildExecutionSurface {
    /// The provider the child inference request will actually go to.
    pub provider: String,
    /// The model id the child inference request will actually go to.
    pub model: String,
    /// The config generation this surface was resolved from. The caller binds
    /// the admitted attempt to this value; a generation change invalidates it.
    pub config_generation: u64,
    /// The tool-description steering resolved from the child's OWN def —
    /// never the parent frame's.
    pub tool_steering: crate::agents::ToolSteering,
    /// The capability posture resolved from the child's OWN def — never the
    /// parent frame's.
    pub posture: crate::agents::PostureResolution,
    /// The context policy resolved from the child's OWN def — used for
    /// handoff-tag inline caps.
    pub context_policy: Option<crate::agents::ContextPolicy>,
    /// The child's actual tool/capability names (its enumerated surface).
    pub tools: Vec<String>,
    /// Whether the attempt carries write authority — it holds a single-writer
    /// lock/write tool, or a `write_scope` confinement was requested for it.
    /// INFORMATIONAL ONLY: this is NOT the concurrent-admission key (a requested
    /// `write_scope` alone never grants concurrency). Concurrent admission is
    /// decided by [`batch_child_concurrently_admissible`] from
    /// `parallel_read_only_eligible` OR the parent-scoped write-admission gate.
    pub write_authority: bool,
    /// Closed derived boolean: true ONLY when a noninteractive child exposes
    /// exclusively registered ordinary [`crate::engine::tool::ToolEffect::ReadOnly`]
    /// operations (plus the structural `return` completion envelope) and NO
    /// approval-required / `Dynamic` / mutating / unknown-unregistered /
    /// write-authority-or-scope / nested-delegation / task-control / scheduling
    /// capability; false whenever any surface component cannot be enumerated.
    pub parallel_read_only_eligible: bool,
}

/// Build the [`ResolvedChildExecutionSurface`] for a child named `name` under
/// `args`. Side-effect-free: it builds the child agent (a pure construction —
/// [`load`] creates no lifecycle state) and derives the surface from the actual
/// built agent, so the surface's identity, posture, tool summary, and derived
/// booleans equal the attempt subsequently built from the same generation.
///
/// On child-agent build or model/mode resolution failure this returns the
/// existing content-safe routing error, so the caller fails BEFORE dispatch and
/// never falls back to the parent posture for a different selected model.
pub fn resolve_child_execution_surface(
    name: &str,
    args: &SpawnArgs,
) -> Result<ResolvedChildExecutionSurface> {
    // Pin the generation BEFORE building the child, and stamp the surface with
    // the pinned value. A config refresh landing between build and stamp can then
    // only make the stamped generation OLDER than reality (so the consumer's
    // start-check reliably detects the change and recomputes), never NEWER (which
    // would falsely match a now-stale surface and skip the recompute).
    let config_generation = args.config.generation();
    let child = load(name, args)?;
    Ok(surface_from_built_child(&child, args, config_generation))
}

/// Whether a batch scheduler may admit this child for CONCURRENT execution. The
/// concurrency KEY is exactly two signals:
///   - `surface.parallel_read_only_eligible` — the surface PROVES the child
///     exposes exclusively registered ordinary read-only operations; OR
///   - `parent_write_admitted` — the child PASSED the existing parent-scoped
///     disjoint-scope write-admission gate (its REAL single-writer capability
///     [`is_write_capable`] plus the batch's Frontier + disjoint-scope policy),
///     decided by the batch scheduler and passed in here.
///
/// `surface.write_authority` is INFORMATIONAL ONLY and is NEVER the concurrency
/// key: a child that merely carries a requested `write_scope` but has no real
/// single-writer capability and did not pass parent write-admission (e.g. a
/// custom/dynamic bash child handed a `write_scope`) is NOT concurrently
/// admissible — `parallel_read_only_eligible` is false for it and
/// `parent_write_admitted` is false, so it runs under the EXCLUSIVE guard. Every
/// other child (a read-only-SOUNDING child whose real surface holds a
/// dynamic/mutating tool, or a nested/task/scheduling child) is likewise NOT
/// concurrently admissible and runs alone.
pub(crate) fn batch_child_concurrently_admissible(
    surface: &ResolvedChildExecutionSurface,
    parent_write_admitted: bool,
) -> bool {
    surface.parallel_read_only_eligible || parent_write_admitted
}

/// Build the execution surface for an already-loaded child, without re-loading.
/// Same result as [`resolve_child_execution_surface`] for the same `(child,
/// args)` — the scheduler uses this to bind a surface to a child it has just
/// built for admission. `config_generation` MUST be the generation pinned
/// BEFORE the child was built (not read here), so the stamp cannot be newer than
/// the build.
pub(crate) fn surface_for_built_child(
    child: &Agent,
    args: &SpawnArgs,
    config_generation: u64,
) -> ResolvedChildExecutionSurface {
    surface_from_built_child(child, args, config_generation)
}

fn surface_from_built_child(
    child: &Agent,
    args: &SpawnArgs,
    config_generation: u64,
) -> ResolvedChildExecutionSurface {
    let write_authority = is_write_capable(child) || args.write_scope.is_some();
    ResolvedChildExecutionSurface {
        provider: child.model.provider_id().to_string(),
        model: child.model.model_id_ref().to_string(),
        config_generation,
        tool_steering: child.tool_steering,
        posture: child.posture.clone(),
        context_policy: child.context_policy.clone(),
        tools: child
            .tools
            .names()
            .into_iter()
            .map(str::to_string)
            .collect(),
        write_authority,
        parallel_read_only_eligible: derive_parallel_read_only_eligible(child, args),
    }
}

/// The closed derivation for [`ResolvedChildExecutionSurface::parallel_read_only_eligible`].
/// Conservative and fail-closed: any capability that cannot be proven a
/// registered ordinary read-only operation makes the whole surface ineligible.
fn derive_parallel_read_only_eligible(child: &Agent, args: &SpawnArgs) -> bool {
    // Only a noninteractive, non-pipeline child can be admitted for concurrent
    // read-only execution. An interactive attempt or a `docs` pipeline stage
    // (routed, never enumerable here) is not eligible.
    if args.interactive || !is_noninteractive(&child.name) || is_docs_pipeline(&child.name) {
        return false;
    }
    // Any write authority (held lock/write tool) or requested write scope, or a
    // nested-delegation (`task`) surface, forecloses eligibility.
    if args.write_scope.is_some() || is_write_capable(child) || is_delegating(child) {
        return false;
    }
    // Every exposed tool must be a registered ordinary read-only operation. The
    // structural `return` completion envelope is the only non-operation tool a
    // delegated leaf carries; it is not a capability, so it does not disqualify.
    // Anything else that is `Dynamic` (bash, search, mcp, schedule, spawn,
    // approval-gated tools) or `Mutating`, that cannot be looked up, OR that is
    // not a REGISTERED ORDINARY built-in operation (a user-authored custom-bash
    // template — even one marked `approval_exempt` whose `effect()` reads
    // `ReadOnly` — can run an arbitrary shell command) makes the surface
    // ineligible.
    let names = child.tools.names();
    if names.iter().all(|&name| name == "return") {
        // A surface with no enumerable ordinary operation is not a positive
        // admission signal.
        return false;
    }
    for &name in &names {
        if name == "return" {
            continue;
        }
        match child.tools.get(name) {
            Some(tool)
                if tool.is_registered_ordinary_operation()
                    && tool.effect() == crate::engine::tool::ToolEffect::ReadOnly => {}
            _ => return false,
        }
    }
    true
}

/// Register the structural `return` tool on `tb` for a **delegated subagent**
/// (implementation note). Every delegated subagent
/// — `builder`/`explore` and any custom subagent — finishes by
/// returning a structured summary envelope, so it holds `return` from session
/// start (cache-safe; the tools array is never mutated mid-session). The `docs`
/// pipeline stages are **exempt** (their answer is the payload), so they never
/// get it; a chat-owning primary (`Build`/`Plan`/`Multireview`) is never
/// delegated to and finishes via `Done`, so it is excluded too. `name` is the
/// agent's own name.
fn with_return_tool(tb: ToolBox, name: &str) -> ToolBox {
    if name == "deepthink" {
        return tb;
    }
    if is_docs_pipeline(name) || is_primary(name) {
        return tb;
    }
    tb.with(Arc::new(crate::tools::return_tool::ReturnTool))
}

/// Whether `name` is a bundled chat-owning **primary** (top-level) agent. Used
/// to exclude primaries from the delegated-subagent `return` tool: a primary is
/// never delegated to and finishes via `Done`.
fn is_primary(name: &str) -> bool {
    crate::agents::is_builtin_primary(name)
}

/// Build an [`Agent`] from a resolved [`crate::agents::AgentDef`] — the
/// path taken for an on-disk override (edited built-in) or a custom
/// agent. The def's `prompt`, `tools`, `temperature`, and (when
/// resolvable) `model` flow into the constructed agent so an edit takes
/// effect on the next run. Invariants were already enforced at load
/// ([`crate::agents::validate_invariants`]); this builds the toolbox from
/// the validated grant.
///
/// When `tools` is absent the agent falls back to its role-default
/// surface: for a built-in name we reuse that built-in's embedded
/// default grant (so an override that only tweaks the prompt keeps the
/// right tools); a custom agent with no grant gets the read-only
/// investigator surface.
pub(crate) fn agent_from_def(def: &crate::agents::AgentDef, args: &SpawnArgs) -> Result<Agent> {
    let effective_vnext_grant = effective_vnext_grant_for(def, args)?;
    let is_assistant = def.vnext.as_ref().map_or(
        args.assistant_identity_prefix.is_some()
            && crate::agents::embedded_default(&def.name).is_none(),
        |definition| definition.execution_kind == crate::agents::ExecutionKind::Assistant,
    );
    if def.name == "deepthink" {
        let model = resolve_agent_model(def, args)?;
        emit_model_override_warning(def, args, &model);
        // Posture follows the child's OWN resolved model, not the root frame.
        let tool_steering = crate::agents::ToolSteering::from_def(def);
        let declared_posture = crate::agents::PostureResolution::from_def(def);
        let posture = args.parent_posture.as_ref().map_or_else(
            || declared_posture.clone(),
            |parent| declared_posture.intersect_parent(parent),
        );
        let mut params = args.params.clone();
        if let Some(temp) = def.temperature {
            params.temperature = Some(temp as f64);
        }
        let role = def.resolved_prompt_for_model(model.provider_id(), model.model_id_ref());
        return Ok(Agent {
            name: def.name.clone(),
            system: compose_system_prompt_for_model(role, &model, args),
            role_prompt: role.to_string(),
            tools: ToolBox::new(),
            model,
            params,
            scan_tool_results: false,
            tool_steering,
            posture,
            context_policy: def.context_policy.clone(),
            lock_identity: args
                .lock_identity
                .clone()
                .unwrap_or_else(|| def.name.clone()),
            write_scope: args.write_scope.clone(),
            delegated: args.delegated,
            delegation_recursion: DelegationRecursionContext {
                enabled: args.delegation_recursion.enabled,
                remaining_depth: 0,
                allowed_targets: Vec::new(),
                same_model_only: false,
            },
            vnext_grant: effective_vnext_grant.clone(),
            env_overlay: args.env_overlay.clone(),
            definition: Some(Arc::new(def.clone())),
            assistant_identity_prefix: args.assistant_identity_prefix.clone(),
            mcp_resolver: mcp_resolver_for(args, def),
        });
    }

    // Resolve the tool-name grant: explicit list, else the role default.
    let grant: Vec<String> = match &def.tools {
        Some(t) => t.clone(),
        None if is_assistant => default_assistant_tools(),
        None => {
            #[cfg(test)]
            if let Some(tools) = test_host_tool_surface(&args.cwd, &def.name) {
                tools
            } else {
                crate::agents::embedded_default(&def.name)
                    .and_then(|d| d.tools)
                    .unwrap_or_else(default_custom_tools)
            }
            #[cfg(not(test))]
            {
                crate::agents::embedded_default(&def.name)
                    .and_then(|d| d.tools)
                    .unwrap_or_else(default_custom_tools)
            }
        }
    };

    let mut tb = ToolBox::new();
    for name in &grant {
        // `spawn` and `schedule` construct legacy Swarm/ephemeral forks
        // outside the v2 child-resolution contract.  Until those forks carry
        // an effective child grant and its admission permit end-to-end, do not
        // expose either legacy fork surface to a v2 definition.  `task` is
        // added below only from the v2 effective delegation grant.
        if def.vnext.is_some() && matches!(name.as_str(), "spawn" | "schedule" | "task") {
            continue;
        }
        tb = match effective_tool_tier(def, name, is_assistant) {
            crate::agents::ToolTier::Enabled => add_tool_by_name(tb, name, def, args)?,
            crate::agents::ToolTier::Discoverable => {
                add_discoverable_tool_by_name(tb, name, def, args)?
            }
            crate::agents::ToolTier::Disabled => tb,
        };
    }
    // vNext deliberately has no `tools:` authority field.  Delegation is the
    // sole declarative request that can cause the host to expose the
    // structural `task` tool, and it is still checked again by the driver
    // immediately before a child is constructed.
    if let (Some(vnext), Some(grant)) = (&def.vnext, &effective_vnext_grant) {
        if grant.agent_id != vnext.agent_id || grant.execution_kind != vnext.execution_kind {
            bail!("vNext effective grant does not match selected definition");
        }
        let targets = vnext_reachable_subagents(
            grant,
            def,
            &args.cwd,
            &args.vnext_local_installation_resolver,
        )?;
        let target_refs: Vec<&str> = targets.iter().map(String::as_str).collect();
        tb = with_task_for_targets(tb, args, &target_refs);
    }
    tb = with_audio_video_tools(tb, def, args)?;
    tb = with_read_image_tools(tb, def, args)?;
    tb = with_ask_image_tools(tb, def, args)?;
    #[cfg(feature = "extended")]
    {
        tb = with_image_generation_tools(tb, def, args)?;
    }
    if !is_internal_agent_def_name(&def.name) || internal_agent_def_uses_custom_tools(&def.name) {
        // Custom-bash tools (webfetch/websearch/…) are config-driven, not part
        // of the named grant — attach them like the built-in factories do.
        tb = with_custom_tools(tb, &args.config, &args.cwd, &non_direct_tier_names(def));
    }
    if !is_internal_agent_def_name(&def.name) {
        // Cross-session recall tools, gated on interactive spawn.
        tb = with_tiered_recall_tools(tb, args, def, is_assistant, &grant)?;
        // `return` (structured-summary envelope, `structured-subagent
        // -return-summary.md`): a delegated subagent finishes by returning a
        // structured summary. An on-disk override of a bundled agent keeps its name,
        // so `with_return_tool`'s name guards exclude a bundled primary/docs
        // override; a custom agent is gated on its `mode` here (a `Primary`-only
        // custom agent is chat-owning, never delegated to, so it gets no `return`).
        let delegated_return = match def.vnext.as_ref() {
            Some(definition) => {
                definition.execution_kind != crate::agents::ExecutionKind::Assistant
            }
            None => def.mode.is_subagent(),
        };
        if crate::agents::embedded_default(&def.name).is_some() || delegated_return {
            tb = with_return_tool(tb, &def.name);
        }
    }
    validate_discoverable_mcp_reachable(def, &tb)?;
    // Per-agent tool-description overrides (prompt
    // `per-agent-tool-definitions.md`): re-word a granted tool's description
    // for this markdown agent. Applied last so it lands on whatever tool of
    // that name is on the box; the schema is never touched, so the tools array
    // stays byte-stable for `(agent, steering)`. Naming a non-granted tool was
    // rejected at load (`validate_invariants`), so an override here always has
    // a matching tool.
    for (tool_name, spec) in &def.tool_descriptions {
        tb = tb.with_override(tool_name, spec.to_override());
    }

    // Model precedence (plan → frontmatter → caller choice → role slot →
    // session). A malformed explicit frontmatter selector fails loudly because
    // it is a direct user setting; unset or unconfigured role slots fall back.
    let model = resolve_agent_model(def, args)?;
    emit_model_override_warning(def, args, &model);
    // The child's posture (tool steering + capability grants) is resolved
    // from its OWN def (issue #75), never inherited from the root frame.
    let tool_steering = crate::agents::ToolSteering::from_def(def);
    let declared_posture = crate::agents::PostureResolution::from_def(def);
    let posture = args.parent_posture.as_ref().map_or_else(
        || declared_posture.clone(),
        |parent| declared_posture.intersect_parent(parent),
    );

    let mut params = args.params.clone();
    if let Some(temp) = def.temperature {
        params.temperature = Some(temp as f64);
    }

    let role = def.resolved_prompt_for_model(model.provider_id(), model.model_id_ref());
    Ok(Agent {
        name: def.name.clone(),
        system: compose_system_prompt_for_model(role, &model, args),
        role_prompt: role.to_string(),
        tools: tb,
        model,
        params,
        scan_tool_results: def
            .scan_tool_results
            .unwrap_or_else(|| crate::agents::default_scan_tool_results(&def.name)),
        tool_steering,
        posture,
        context_policy: def.context_policy.clone(),
        lock_identity: args
            .lock_identity
            .clone()
            .unwrap_or_else(|| def.name.clone()),
        write_scope: args.write_scope.clone(),
        delegated: args.delegated,
        delegation_recursion: args.delegation_recursion.clone(),
        vnext_grant: effective_vnext_grant,
        env_overlay: args.env_overlay.clone(),
        definition: Some(Arc::new(def.clone())),
        assistant_identity_prefix: args.assistant_identity_prefix.clone(),
        mcp_resolver: mcp_resolver_for(args, def),
    })
}

fn emit_model_override_warning(def: &crate::agents::AgentDef, args: &SpawnArgs, model: &Model) {
    if (args.model_override.is_some() || args.delegation_model.is_some() || def.model.is_some())
        && let Some(warning) = def.model_override_warning(model.provider_id(), model.model_id_ref())
    {
        tracing::warn!(agent = %def.name, provider = %model.provider_id(), model = %model.model_id_ref(), %warning, "agent model override is outside suggested models");
    }
}

fn effective_vnext_grant_for(
    def: &crate::agents::AgentDef,
    args: &SpawnArgs,
) -> Result<Option<crate::agents::EffectiveVnextGrant>> {
    let Some(definition) = &def.vnext else {
        return Ok(None);
    };
    if let Some(grant) = &args.vnext_grant {
        if grant.agent_id != definition.agent_id
            || grant.execution_kind != definition.execution_kind
        {
            bail!("vNext effective grant does not match selected definition");
        }
        return Ok(Some(grant.clone()));
    }
    let Some(parent) = &args.parent_vnext_grant else {
        let Some(host) = &args.vnext_host_policy else {
            // A vNext manifest is an authority request only. The absence of a
            // host policy intentionally builds a no-task agent, not a
            // permissive compatibility projection.
            return Ok(None);
        };
        return def.resolve_vnext_grant(host).map(Some);
    };
    let Some(parent_delegation) = &parent.delegation else {
        bail!("vNext parent has no live delegation grant");
    };
    let references: Vec<_> = parent_delegation
        .allowed_children
        .iter()
        .filter(|reference| {
            reference.is_self() && parent.agent_id == definition.agent_id
                || matches!(reference,
            crate::agents::AllowedChild::PortableRef { portable_agent_ref }
                if portable_agent_ref == &definition.agent_id
                    || portable_agent_ref == &def.name
                    || parent_delegation.package_children.get(portable_agent_ref.as_str())
                        == Some(&definition.agent_id)
                    || parent_delegation
                        .package_children
                        .values()
                        .any(|id| id == &definition.agent_id))
                || matches!(reference,
                    crate::agents::AllowedChild::LocalInstallation { installation_id }
                        if definition.is_local()
                            && args
                                .vnext_local_installation_resolver
                                .matches_definition(*installation_id, &def.name, def))
        })
        .collect();
    let [reference] = references.as_slice() else {
        bail!(
            "vNext child `{}` requires exactly one resolved parent installation reference",
            definition.agent_id,
        );
    };
    definition
        .resolve_child_grant(&parent.host_policy, parent, reference)
        .map(Some)
}

/// Default tool grant for a custom agent that names no `tools:` — the
/// read-only investigator surface (`explore`'s grant). Conservative:
/// never includes write/lock or structural-delegation tools.
fn default_custom_tools() -> Vec<String> {
    ["read", "bash", "code", "graph", "search"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Test-only host tool-surface sidecar (`.cockpit/agents/<name>.tools.json`).
/// v2 markdown cannot declare `tools:`; concurrent-admission tests that need a
/// constrained host surface write this sidecar beside the agent document so
/// admission/build re-reads pick up the projected grant without reviving the
/// author-facing field.
#[cfg(test)]
fn test_host_tool_surface(cwd: &Path, name: &str) -> Option<Vec<String>> {
    let path = cwd
        .join(".cockpit")
        .join("agents")
        .join(format!("{name}.tools.json"));
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

fn default_assistant_tools() -> Vec<String> {
    let mut tools = default_custom_tools();
    tools.extend(
        [
            "mcp",
            "session_search",
            "session_read",
            "session_lineage_search",
            "skill_manage",
        ]
        .into_iter()
        .map(str::to_string),
    );
    tools
}

/// Append the tool named `name` to `tb`. Structural tools (`task`) are
/// wired with the def's reachable subagents. Unknown names are skipped
/// silently here because they were already rejected at load time by
/// [`crate::agents::validate_invariants`]; the custom-bash tools are
/// attached separately, so a name not handled here is a no-op.
fn add_tool_by_name(
    tb: ToolBox,
    name: &str,
    def: &crate::agents::AgentDef,
    args: &SpawnArgs,
) -> Result<ToolBox> {
    materialize_tool_by_name(tb, name, Some(def), args)
}

/// The subagents a `task`-granting agent may delegate to. For `Plan` the
/// bundled reachable set is the read-only investigator (`explore`); for everyone else it is the `Build` cast
/// (`builder`/`explore`/`docs`). Either way, any user-authored custom agent
/// whose `mode` makes it reachable as a subagent (`subagent`/`all`) is
/// appended. Each is listed once, minus the caller itself to avoid a
/// self-delegation loop. Honors the `mode` field for reachability per
/// implementation note.
fn reachable_subagents(
    def: &crate::agents::AgentDef,
    config: &crate::daemon::session_worker::SessionConfigHandle,
    cwd: &Path,
) -> Vec<String> {
    let mut out = if def.name == "Plan" {
        plan_subagents(cwd)
    } else {
        build_subagents(config, cwd)
    };
    out.retain(|s| *s != def.name);
    out
}

pub(crate) async fn reachable_subagent_names(
    parent_agent: &str,
    config: &crate::daemon::session_worker::SessionConfigHandle,
    cwd: &Path,
    assistant_db: &crate::db::Db,
) -> Vec<String> {
    match crate::agents::resolve_with_assistant_db(cwd, parent_agent, assistant_db).await {
        Ok(Some(def)) => reachable_subagents(&def, config, cwd),
        Ok(None) | Err(_) => Vec::new(),
    }
}

pub(crate) async fn unknown_agent_rejection(
    cwd: &Path,
    config: &crate::daemon::session_worker::SessionConfigHandle,
    parent_agent: &str,
    child_agent: &str,
    assistant_db: &crate::db::Db,
) -> Option<String> {
    if child_agent == "docs" {
        return None;
    }
    if child_agent != parent_agent && !matches!(child_agent, "docs-resolver" | "docs-answerer") {
        match crate::agents::resolve_with_assistant_db(cwd, child_agent, assistant_db).await {
            Ok(Some(_)) => return None,
            Ok(None) => {}
            Err(_) => return None,
        }
    }

    let reachable = reachable_subagent_names(parent_agent, config, cwd, assistant_db).await;
    if reachable.is_empty() {
        Some(format!(
            "unknown agent `{child_agent}`, and no subagents are reachable from `{parent_agent}`. Re-issue `task` with a reachable agent name."
        ))
    } else {
        Some(format!(
            "unknown agent `{child_agent}`. Reachable agents from `{parent_agent}`: {}. Re-issue `task` with one of these names.",
            reachable.join(", ")
        ))
    }
}

/// The bundled reachable subagent set for `Plan` plus any user-authored
/// custom subagent (`mode` `subagent`/`all`).
fn plan_subagents(cwd: &Path) -> Vec<String> {
    let mut out: Vec<String> = vec!["explore".to_string(), "history".to_string()];
    append_custom_subagents(&mut out, cwd);
    out
}

/// The bundled reachable subagent set (`builder`/`explore`/`docs`) plus any
/// user-authored custom agent whose `mode` makes it reachable as a
/// subagent (`subagent`/`all`). Shared by the bundled `Build` factory and
/// the generic [`reachable_subagents`] so both honor the `mode` field for
/// reachability (implementation note). Each name appears
/// once; the bundled set leads so the cached prefix stays stable when no
/// custom agents are present.
fn build_subagents(
    config: &crate::daemon::session_worker::SessionConfigHandle,
    cwd: &Path,
) -> Vec<String> {
    let mut out: Vec<String> = vec![
        "builder".to_string(),
        "explore".to_string(),
        "history".to_string(),
        "docs".to_string(),
    ];
    if computer_subagent_reachable(config, cwd) {
        out.push("computer".to_string());
    }
    if config.extended().deepthink.enabled {
        out.push("deepthink".to_string());
    }
    append_custom_subagents(&mut out, cwd);
    out
}

fn add_deepthink_if_enabled(
    out: &mut Vec<String>,
    config: &crate::daemon::session_worker::SessionConfigHandle,
) {
    if config.extended().deepthink.enabled && !out.iter().any(|name| name == "deepthink") {
        out.push("deepthink".to_string());
    }
}

fn recursive_targets(
    config: &crate::daemon::session_worker::SessionConfigHandle,
    base: &[&str],
) -> Vec<String> {
    let mut out = base
        .iter()
        .map(|target| target.to_string())
        .collect::<Vec<_>>();
    add_deepthink_if_enabled(&mut out, config);
    out
}

/// Append every user-authored custom agent whose `mode` makes it reachable
/// as a subagent (`subagent`/`all`) to `out`, skipping names already
/// present. Shared by [`build_subagents`] and [`plan_subagents`] so both
/// honor the `mode` field for reachability the same way
/// (implementation note).
fn append_custom_subagents(out: &mut Vec<String>, cwd: &Path) {
    for listing in crate::agents::list_all(cwd) {
        if !matches!(listing.kind, crate::agents::AgentKind::Custom) {
            continue;
        }
        if let Ok(custom) = &listing.def
            && (custom.mode.is_subagent()
                || custom.vnext.as_ref().is_some_and(|definition| {
                    definition.execution_kind != crate::agents::ExecutionKind::Assistant
                }))
            && !out.contains(&listing.name)
        {
            out.push(listing.name);
        }
    }
}

/// Resolve effective portable vNext child references to the local definition
/// names the existing task wire protocol carries. Local-installation references
/// resolve only through the daemon-injected exact UUID binding seam; they are
/// never guessed from a display name or silently omitted.
fn vnext_reachable_subagents(
    grant: &crate::agents::EffectiveVnextGrant,
    parent: &crate::agents::AgentDef,
    cwd: &Path,
    local_installations: &crate::agents::LocalInstallationResolver,
) -> Result<Vec<String>> {
    use crate::agents::AllowedChild;
    let listings = crate::agents::list_all(cwd);
    let mut resolved = Vec::new();
    let Some(delegation) = &grant.delegation else {
        return Ok(resolved);
    };
    for reference in &delegation.allowed_children {
        match reference {
            AllowedChild::LocalInstallation { installation_id } => {
                let binding = local_installations.resolve(*installation_id)?;
                // The DB-backed assistant resolver runs at task launch.  Do
                // not duplicate it here with a disk-only lookup; preserve the
                // exact UUID→trusted launch target binding and validate the
                // selected vNext definition/kind again at the factory seam.
                resolved.push(binding.launch_target.clone());
            }
            AllowedChild::PortableRef { portable_agent_ref }
                if portable_agent_ref == crate::agents::SELF_CHILD_REF =>
            {
                resolved.push(crate::agents::SELF_CHILD_REF.to_string());
            }
            AllowedChild::PortableRef { portable_agent_ref } => {
                if let Some(private) =
                    parent
                        .private_subagents
                        .get(portable_agent_ref)
                        .or_else(|| {
                            parent.private_subagents.values().find(|child| {
                                child
                                    .vnext
                                    .as_ref()
                                    .is_some_and(|vnext| vnext.agent_id == *portable_agent_ref)
                            })
                        })
                {
                    if listings.iter().any(|listing| {
                        listing.name == private.name
                            || listing
                                .def
                                .as_ref()
                                .ok()
                                .and_then(|def| def.vnext.as_ref())
                                .is_some_and(|vnext| vnext.agent_id == *portable_agent_ref)
                    }) {
                        tracing::warn!(
                            parent = %parent.name,
                            child = %private.name,
                            portable = %portable_agent_ref,
                            "package-private subagent shadows a global agent of the same identity"
                        );
                    }
                    resolved.push(private.name.clone());
                    continue;
                }
                let matches: Vec<_> = listings
                    .iter()
                    .filter_map(|listing| {
                        let child = listing.def.as_ref().ok()?;
                        let child_vnext = child.vnext.as_ref()?;
                        (child_vnext.agent_id == *portable_agent_ref)
                            .then_some((listing.name.clone(), child_vnext.execution_kind))
                    })
                    .collect();
                let [(name, kind)] = matches.as_slice() else {
                    bail!(
                        "vNext portable child `{portable_agent_ref}` must resolve to exactly one local installation (found {})",
                        matches.len()
                    );
                };
                if grant.permits_child(reference, *kind) {
                    resolved.push(name.clone());
                }
            }
        }
    }
    Ok(resolved)
}

/// Resolve the model an agent spawns under.
fn resolve_agent_model(def: &crate::agents::AgentDef, args: &SpawnArgs) -> Result<Arc<Model>> {
    // vNext definitions must interpret every explicit model through their
    // prepared primary slot (or the root-only derived-definition path). A raw
    // SpawnArgs override is not authority to bypass the installed slot set.
    if def.vnext.is_some() {
        return resolve_vnext_slot_model(def, args);
    }
    // Legacy definitions retain the historical plan/frontmatter precedence.
    if let Some(model) = &args.model_override {
        return Ok(model.clone());
    }
    let (extended, providers) = crate::engine::model_roles::load_model_role_config(&args.config);
    match crate::engine::model_roles::resolve_delegated_model_with_store(
        &def.name,
        def.model.as_deref(),
        args.delegation_model.as_ref(),
        &extended,
        &providers,
        &args.model,
        args.credential_store.clone(),
    ) {
        Ok(model) => Ok(model),
        Err(crate::engine::model_roles::SelectorResolution::InvalidLiteral(message)) => {
            bail!("invalid explicit subagent model selector: {message}")
        }
        Err(crate::engine::model_roles::SelectorResolution::Unset) => Ok(args.model.clone()),
    }
}

/// vNext children and installed roots run their primary-slot default unless a
/// parent-named selector names one of the slot's allowed models. Naming
/// anything else is a structured refusal (never a silent session-model inherit).
fn resolve_vnext_slot_model(def: &crate::agents::AgentDef, args: &SpawnArgs) -> Result<Arc<Model>> {
    let vnext = def
        .vnext
        .as_ref()
        .expect("resolve_vnext_slot_model requires a vNext def");
    let slot = vnext
        .model_slots
        .get("primary")
        .context("vNext definition is missing the required primary slot")?;
    let (extended, _) = crate::engine::model_roles::load_model_role_config(&args.config);
    let mut routes = prepared_primary_slot_routes_for(def, args)?;
    if routes.is_empty() {
        return resolve_unprepared_vnext_primary_slot(def, slot, args, &extended);
    }
    let providers = args.config.providers();
    routes.retain(|route| crate::agents::prepared_route_is_compatible(slot, route, &providers));
    ensure!(
        routes.iter().any(|route| route.is_default),
        "prepared vNext primary-slot default no longer satisfies the current provider generation and hard requirements"
    );
    let allowed_label = format_prepared_route_list(&routes);

    if let Some(model) = &args.model_override {
        let matching = routes.iter().find(|route| {
            route.model_id == model.model_id_ref()
                && (route.provider_profile_handle == model.provider_id()
                    || route.provider_id == model.provider_id())
        });
        if let Some(route) = matching {
            return model_from_prepared_route(route, args).with_context(|| {
                format!(
                    "loading selected prepared vNext route `{}:{}`",
                    route.provider_id, route.model_id
                )
            });
        }
        if args.delegated {
            bail!(
                "explicit model override `{}:{}` is not in vNext child `{}` primary-slot routes: {allowed_label}",
                model.provider_id(),
                model.model_id_ref(),
                def.name
            );
        }
        // Root out-of-set selection is the issue #75 derived-definition path:
        // preserve the exact pinned definition/posture, substitute only the
        // execution model, and surface the widening as a lint-level warning.
        tracing::warn!(
            agent = %def.name,
            provider = %model.provider_id(),
            model = %model.model_id_ref(),
            allowed_routes = %allowed_label,
            "vNext root model override is outside the prepared slot set; using a derived definition with unchanged posture"
        );
        return Ok(model.clone());
    }

    if let Some(selector) = &args.delegation_model {
        if !extended.agent_chooses_subagent_model {
            bail!(
                "parent-named model selector is refused because agent_chooses_subagent_model is off; allowed routes: {allowed_label}"
            );
        }
        let crate::engine::model_roles::DelegationModelSelector::Exact { selector, .. } = selector
        else {
            bail!(
                "parent-named category selector is refused; child slot allowed routes: {allowed_label}"
            );
        };
        let (provider, model) = crate::engine::model_roles::split_selector(selector).ok_or_else(|| {
            anyhow::anyhow!(
                "parent-named model `{selector}` is not in the child slot allowed route set: {allowed_label}"
            )
        })?;
        let Some(route) = routes
            .iter()
            .find(|route| route.provider_id == provider && route.model_id == model)
        else {
            bail!(
                "parent-named model `{selector}` is not in the child slot allowed route set: {allowed_label}"
            );
        };
        return model_from_prepared_route(route, args)
            .with_context(|| format!("loading prepared vNext child route `{selector}`"));
    }

    let default = routes
        .iter()
        .find(|route| route.is_default)
        .context("prepared vNext primary-slot routes lost their default")?;
    // A prepared default is the only non-selector route for vNext roots and
    // children. Authored provider ids in `modelSlots.primary.models` remain
    // advisory only once a durable route has been chosen.
    let _ = slot;
    model_from_prepared_route(default, args).with_context(|| {
        format!(
            "loading prepared vNext default route `{}:{}`",
            default.provider_id, default.model_id
        )
    })
}

/// Unprepared empty `models` means any compatible offering (Stage 4), so the
/// session model is inherited and a parent-named exact selector is still
/// honored. A non-empty authored list is authority for delegated children:
/// they run [`ModelSlot::default_model`] rather than silently inheriting a
/// session model outside the allowed set. Unprepared roots keep the
/// session/persisted model even when the list is non-empty (Stage 5: no
/// installation keeps today's `active_model` path; resume keeps the persisted
/// selection; the slot default applies from the next fresh prepared session).
/// A root picker override is accepted via `model_override`. A raw delegated
/// override is not authority to bypass the slot.
fn resolve_unprepared_vnext_primary_slot(
    def: &crate::agents::AgentDef,
    slot: &crate::agents::ModelSlot,
    args: &SpawnArgs,
    extended: &crate::config::extended::ExtendedConfig,
) -> Result<Arc<Model>> {
    if let Some(selector) = &args.delegation_model {
        return resolve_unprepared_vnext_delegation_selector(def, slot, args, extended, selector);
    }
    if let Some(model) = &args.model_override
        && !args.delegated
    {
        tracing::warn!(
            agent = %def.name,
            provider = %model.provider_id(),
            model = %model.model_id_ref(),
            "vNext root model override derived from the pinned definition without prepared slot routes"
        );
        return Ok(model.clone());
    }
    if slot.models.is_empty() {
        return Ok(args.model.clone());
    }
    if !args.delegated {
        // Unprepared roots keep today's active_model / persisted resume path.
        return Ok(args.model.clone());
    }
    let default = slot
        .default_model()
        .context("vNext primary slot with a non-empty models list lost its default")?;
    model_from_unprepared_slot_ids(
        def,
        args,
        &default.provider_id,
        &default.model_id,
        &format!(
            "authored default `{}:{}`",
            default.provider_id, default.model_id
        ),
    )
}

fn resolve_unprepared_vnext_delegation_selector(
    def: &crate::agents::AgentDef,
    slot: &crate::agents::ModelSlot,
    args: &SpawnArgs,
    extended: &crate::config::extended::ExtendedConfig,
    selector: &crate::engine::model_roles::DelegationModelSelector,
) -> Result<Arc<Model>> {
    let allowed_label = format_slot_allowed_models(slot);
    if !extended.agent_chooses_subagent_model {
        bail!(
            "parent-named model selector is refused because agent_chooses_subagent_model is off; allowed routes: {allowed_label}"
        );
    }
    let crate::engine::model_roles::DelegationModelSelector::Exact { selector, .. } = selector
    else {
        bail!(
            "parent-named category selector is refused; child slot allowed routes: {allowed_label}"
        );
    };
    let (provider, model) = crate::engine::model_roles::split_selector(selector).ok_or_else(|| {
        anyhow::anyhow!(
            "parent-named model `{selector}` is not in the child slot allowed route set: {allowed_label}"
        )
    })?;
    if !slot.models.is_empty()
        && !slot
            .models
            .iter()
            .any(|allowed| allowed.provider_id == provider && allowed.model_id == model)
    {
        bail!(
            "parent-named model `{selector}` is not in the child slot allowed route set: {allowed_label}"
        );
    }
    model_from_unprepared_slot_ids(
        def,
        args,
        &provider,
        &model,
        &format!("parent-named route `{selector}`"),
    )
}

fn model_from_unprepared_slot_ids(
    def: &crate::agents::AgentDef,
    args: &SpawnArgs,
    provider: &str,
    model: &str,
    route_label: &str,
) -> Result<Arc<Model>> {
    Ok(Arc::new(
        crate::engine::model::Model::for_provider_optional_store(
            &args.config.providers(),
            provider,
            model,
            args.model.session_redact_table(),
            args.credential_store.clone(),
        )
        .with_context(|| format!("loading unprepared vNext `{}` {route_label}", def.name))?
        .with_shutdown_gate(args.model.shutdown_gate()),
    ))
}

fn format_slot_allowed_models(slot: &crate::agents::ModelSlot) -> String {
    if slot.models.is_empty() {
        return "any compatible offering".to_string();
    }
    let default = slot.default_model();
    slot.models
        .iter()
        .map(|model| {
            let marker = if default.is_some_and(|default| {
                default.provider_id == model.provider_id && default.model_id == model.model_id
            }) {
                " [default]"
            } else {
                ""
            };
            format!("{}:{}{marker}", model.provider_id, model.model_id)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn prepared_primary_slot_routes_for(
    def: &crate::agents::AgentDef,
    args: &SpawnArgs,
) -> Result<Vec<crate::agents::PreparedPrimarySlotRoute>> {
    if !args.delegated {
        return args
            .vnext_local_installation_resolver
            .root_primary_slot_routes_for_launch_target(&def.name)
            .map(|routes| routes.unwrap_or_default());
    }
    let Some(parent) = &args.parent_vnext_grant else {
        return Ok(Vec::new());
    };
    args.vnext_local_installation_resolver
        .primary_slot_routes_for_authorized_child(parent, def)
        .map(|routes| routes.unwrap_or_default())
}

fn format_prepared_route_list(routes: &[crate::agents::PreparedPrimarySlotRoute]) -> String {
    routes
        .iter()
        .map(|route| {
            let default = if route.is_default { " [default]" } else { "" };
            format!("{}:{}{}", route.provider_id, route.model_id, default)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn model_from_prepared_route(
    route: &crate::agents::PreparedPrimarySlotRoute,
    args: &SpawnArgs,
) -> Result<Arc<Model>> {
    anyhow::ensure!(
        route.hard_capability_verified,
        "prepared vNext route is not hard-verified"
    );
    let providers = args.config.providers();
    Ok(Arc::new(
        crate::engine::model::Model::for_provider_optional_store(
            &providers,
            &route.provider_profile_handle,
            &route.model_id,
            args.model.session_redact_table(),
            args.credential_store.clone(),
        )?
        .with_shutdown_gate(args.model.shutdown_gate()),
    ))
}

/// `Build` — the user-facing, **write-capable** primary agent. Owns the chat
/// when the focus is *making the change* (GOALS §3a). It can write directly
/// (it holds the lock/write tools, arbitrated by the single lock authority),
/// but its intent is **delegate-eager**: hand substantive feature work to
/// `builder` via `task` and direct-write only small single-scope changes.
pub fn build(args: &SpawnArgs) -> Agent {
    let def = crate::agents::embedded_default("Build").expect("Build has an embedded definition");
    // Reachable subagents: the bundled set plus any custom subagent the
    // user has added (implementation note discoverability).
    let subs = build_subagents(&args.config, &args.cwd);
    let sub_refs: Vec<&str> = subs.iter().map(String::as_str).collect();
    let base_tools = with_write_tools(with_build_family_intel(
        ToolBox::new()
            .with(Arc::new(crate::tools::read::ReadTool))
            .with(Arc::new(crate::tools::bash::BashTool::new())),
    ))
    // The `schedule` meta-tool (GOALS §22) — fixed minimal schema, so
    // the tools array stays byte-stable as branches are enabled.
    // Structural: intercepted by the engine and routed to the
    // driver-owned async-job authority.
    .with(Arc::new(crate::tools::schedule::ScheduleTool))
    // `question` (GOALS §3b): structural — blocks the turn until
    // the user answers.
    .with(Arc::new(crate::tools::question::QuestionTool))
    // `skill` (GOALS §5): manual on-demand skill loading.
    .with(Arc::new(crate::tools::skill::SkillTool))
    // Guarded writes to configured skill roots. The mutation service owns
    // validation, protection, provenance, and atomicity.
    .with(Arc::new(crate::tools::skill_manage::SkillManageTool))
    // External-harness delegation (GOALS §6,
    // implementation note): list configured
    // harnesses + invoke one as an external leaf subagent.
    // Granted to the primaries `Build`/`Plan` only; never to
    // leaf subagents. `harness_invoke` is itself a leaf
    // delegation (the external harness gets no cockpit tools).
    .with(Arc::new(crate::tools::harness::HarnessListTool))
    .with(Arc::new(crate::tools::harness::HarnessInvokeTool))
    // MCP (GOALS §18a): Monty Python sandbox.
    .with(Arc::new(crate::tools::mcp_tool::McpTool));
    let tools = with_recall_tools(
        with_custom_tools(
            with_task_for_targets(base_tools, args, &sub_refs),
            &args.config,
            &args.cwd,
            &std::collections::BTreeSet::new(),
        ),
        args,
    );
    // Per-agent intent (prompt `per-agent-tool-definitions.md`): `Build` is
    // delegate-eager — substantive feature work and follow-up implementation
    // iterations go to fresh `builder` tasks, while `Build` decides, briefs,
    // and reports. The override re-words only the description for this agent;
    // the tool ID + schema are unchanged, so the tools array stays byte-stable
    // for `(Build, steering)`.
    let tools = tools.with_override(
        "task",
        crate::engine::tool::ToolDescOverride {
            text: Some(
                "Delegate substantive feature work to a subagent (builder writes, explore investigates); if task returns backgrounded JSON, the call is closed but the child is detached/result-pending, so use task_call_id controls or the async result rather than duplicate work; use docs by default for unfamiliar or version-sensitive dependency APIs"
                    .to_string(),
            ),
            verbose_text: Some(
                "Delegate substantive implementation instead of doing it inline: hand each \
                 well-scoped piece to `builder` to write/edit files, or to `explore` for \
                 read-only investigation, with a complete standalone brief (goal, constraints, \
                 exact files, what \"done\" looks like). Each `builder` task is one \
                 implementation slice, not a bundle of unrelated asks. If the user asks for a \
                 follow-up implementation iteration after `builder` returns, start a fresh \
                 `builder` brief seeded with the prior result summary, relevant changed files, \
                 and the new request. For how to USE a third-party dependency's API, your first \
                 move is `docs` (JSON `{package, question}`), including dependency questions \
                 found while preparing a `builder` brief; skip it only when exact usage is \
                 clearly established in already-read local code. If a task returns a backgrounded \
                 task_delegation JSON envelope, the tool call is closed but the child is detached \
                 with result_pending=true; do not treat it as the report or redelegate solely \
                 because it backgrounded. Continue the conversation and act on the async result, \
                 or poll status/query/list by task_call_id. Read each child status/error; steer \
                 only applies at the next child turn boundary if still running/actionable. Your \
                 own inline work is limited to orchestration and short read-only lookups."
                    .to_string(),
            ),
        },
    );

    let model = resolve_agent_model(&def, args)
        .expect("Build embedded definition resolves a conversational model");
    let tool_steering = crate::agents::ToolSteering::from_def(&def);
    let posture = crate::agents::PostureResolution::from_def(&def);
    let role = BUILD_PROMPT;
    let params = params_with_direct_computer(args, &model);
    Agent {
        name: "Build".to_string(),
        system: compose_system_prompt_for_model(role, &model, args),
        role_prompt: role.to_string(),
        tools,
        model,
        params,
        scan_tool_results: true,
        tool_steering,
        posture,
        context_policy: def.context_policy.clone(),
        lock_identity: args
            .lock_identity
            .clone()
            .unwrap_or_else(|| "Build".to_string()),
        write_scope: args.write_scope.clone(),
        delegated: args.delegated,
        delegation_recursion: args.delegation_recursion.clone(),
        vnext_grant: args.vnext_grant.clone(),
        env_overlay: args.env_overlay.clone(),
        definition: Some(Arc::new(def)),
        assistant_identity_prefix: args.assistant_identity_prefix.clone(),
        mcp_resolver: mcp_resolver_for_cwd(args),
    }
}

fn embedded_agent(name: &str, args: &SpawnArgs) -> Agent {
    let def = crate::agents::embedded_default(name).expect("embedded agent definition exists");
    agent_from_def(&def, args).expect("embedded agent definition materializes")
}

/// `builder` — a **write-capable** worker subagent. Holds file locks; runs
/// bash; applies edits. Its surface mirrors `Build`'s write + full-intel +
/// bash + skill + MCP + web, **minus** general feature-delegation: it
/// keeps `task` only to reach the `docs` pipeline and has no `schedule`. Intent:
/// **do-it-yourself** within its scope; return out-of-scope work up via the
/// structured-return envelope. Caller-determined interactivity: interactive
/// when spawned from `Build` (GOALS §3a/§3b).
pub fn builder(args: &SpawnArgs) -> Agent {
    embedded_agent("builder", args)
}

/// `explore` — read-only investigator. Leaf in the invocation tree
/// (no `task` of its own). Runs noninteractively from
/// `Build`'s perspective: the primary agent dispatches it
/// via `task(agent="explore", …)` and gets a single text report back
/// as the tool result. The user sees the call rendered like any other
/// tool in the primary agent's history.
pub fn explore(args: &SpawnArgs) -> Agent {
    embedded_agent("explore", args)
}

/// `history` — read-only recall worker. It searches prior sessions and
/// compaction lineage in its own context, then returns a short report.
pub fn history(args: &SpawnArgs) -> Agent {
    embedded_agent("history", args)
}

/// `deepthink` — optional tool-free reasoning worker. It is intentionally a
/// leaf: no read/bash/MCP/custom tools, no `return`, no recursive `task`, and
/// no grant application. It receives only the caller-authored brief plus
/// context already materialized in the delegation prompt.
pub fn deepthink(args: &SpawnArgs) -> Agent {
    let def =
        crate::agents::embedded_default("deepthink").expect("deepthink has an embedded definition");
    let model = resolve_agent_model(&def, args)
        .expect("deepthink embedded definition resolves a conversational model");
    Agent {
        name: "deepthink".to_string(),
        system: compose_system_prompt_for_model(DEEPTHINK_PROMPT, &model, args),
        role_prompt: DEEPTHINK_PROMPT.to_string(),
        tools: ToolBox::new(),
        tool_steering: crate::agents::ToolSteering::from_def(&def),
        posture: crate::agents::PostureResolution::from_def(&def),
        model,
        params: args.params.clone(),
        scan_tool_results: false,
        context_policy: def.context_policy.clone(),
        lock_identity: args
            .lock_identity
            .clone()
            .unwrap_or_else(|| "deepthink".to_string()),
        write_scope: args.write_scope.clone(),
        delegated: args.delegated,
        delegation_recursion: DelegationRecursionContext {
            enabled: args.delegation_recursion.enabled,
            remaining_depth: 0,
            allowed_targets: Vec::new(),
            same_model_only: false,
        },
        vnext_grant: args.vnext_grant.clone(),
        env_overlay: args.env_overlay.clone(),
        definition: Some(Arc::new(def)),
        assistant_identity_prefix: args.assistant_identity_prefix.clone(),
        mcp_resolver: mcp_resolver_for_cwd(args),
    }
}

/// `computer` — provider-native computer-use worker. It never inherits a
/// non-vision parent model: the factory selects an eligible
/// vision-capable, subagent-invokable model with a native computer contract
/// and refuses loudly when none exists.
pub fn computer(args: &SpawnArgs) -> Result<Agent> {
    let (_extended, providers) = args.config.configs();
    let Some((provider_id, model_id, native_computer)) =
        computer_subagent_candidate(&providers, &args.cwd)
    else {
        bail!(
            "computer-use subagent requires a configured vision-capable, subagent-invokable model with native computer_use enabled"
        );
    };
    // The worker route is a *sensitive* route — computer use ships screenshots
    // of the user's desktop — so it constructs the paired custody/payload type,
    // not the payload-less eligibility check the candidate scan uses. The
    // session redaction table is in hand here, so the payload carries a real
    // rendering policy for the resolved class.
    let session_redact = args.effective_model().session_redact_table();
    let custody = crate::engine::model_roles::custody_for_trust(
        providers.resolve_trust(&provider_id, &model_id),
    );
    let worker_selector = format!("{provider_id}:{model_id}");
    let request = crate::config::providers::SensitiveModelPolicyRequest::new(
        computer_use_criteria(&worker_selector),
        custody,
        crate::engine::model_roles::custody_payload_for(custody, &session_redact),
    )
    .map_err(|error| anyhow::anyhow!("computer-use model custody: {error}"))?;
    let resolved = providers
        .resolve_sensitive_model_policy(&request)
        .map_err(|error| anyhow::anyhow!("computer-use model custody: {error}"))?;
    tracing::debug!(
        custody = resolved.custody.as_str(),
        granted = resolved.trusted_custody_grant().is_some(),
        routing = %serde_json::to_string(&resolved.policy.routing_diagnostics()).unwrap_or_default(),
        "computer-use subagent custody"
    );
    let model = Arc::new(crate::engine::model::Model::for_provider_optional_store(
        &providers,
        &provider_id,
        &model_id,
        session_redact,
        args.credential_store.clone(),
    )?);
    let caps = providers.resolve_effective_model_capabilities(
        model.provider_id(),
        model.model_id_ref(),
        providers.resolution_generation,
    );
    if !caps.supports_image_input() {
        bail!(
            "computer-use subagent requires a vision-capable model; `{}`:`{}` is not vision-capable",
            model.provider_id(),
            model.model_id_ref()
        );
    }
    let mut child_args = args.clone();
    child_args.model = model;
    child_args.params.native_computer = Some(native_computer);
    let def = crate::agents::embedded_internal_default("computer")
        .expect("computer has an internal agent definition");
    let mut agent = agent_from_def(&def, &child_args)?;
    agent.delegation_recursion = DelegationRecursionContext {
        enabled: args.delegation_recursion.enabled,
        remaining_depth: 0,
        allowed_targets: Vec::new(),
        same_model_only: false,
    };
    Ok(agent)
}

/// `scout` — read-only recursive review worker. Its base surface mirrors
/// `explore` plus `spawn` and `return`; it holds no write/lock tools, no
/// `task`, no MCP, and no docs-only grep/glob. Used by the hidden
/// `Multireview` primary and by deeper scout recursion.
pub fn scout(args: &SpawnArgs) -> Agent {
    let def = crate::agents::embedded_default("scout").expect("scout has an embedded definition");
    let tools = with_recall_tools(
        with_custom_tools(
            with_full_intel(
                ToolBox::new()
                    .with(Arc::new(crate::tools::read::ReadTool))
                    .with(Arc::new(crate::tools::bash::BashTool::new())),
            )
            .with(Arc::new(crate::tools::spawn::SpawnTool::for_depth(
                args.swarm_depth,
                args.swarm_max_depth,
            ))),
            &args.config,
            &args.cwd,
            &std::collections::BTreeSet::new(),
        ),
        args,
    );
    let tools = with_return_tool(tools, "scout");

    let model = resolve_agent_model(&def, args)
        .expect("scout embedded definition resolves a conversational model");
    let tool_steering = crate::agents::ToolSteering::from_def(&def);
    let posture = crate::agents::PostureResolution::from_def(&def);
    let role = SCOUT_PROMPT;
    Agent {
        name: "scout".to_string(),
        system: compose_system_prompt_for_model(role, &model, args),
        role_prompt: role.to_string(),
        tools,
        model,
        params: args.params.clone(),
        scan_tool_results: false,
        tool_steering,
        posture,
        context_policy: def.context_policy.clone(),
        lock_identity: args
            .lock_identity
            .clone()
            .unwrap_or_else(|| "scout".to_string()),
        write_scope: args.write_scope.clone(),
        delegated: args.delegated,
        delegation_recursion: args.delegation_recursion.clone(),
        vnext_grant: args.vnext_grant.clone(),
        env_overlay: args.env_overlay.clone(),
        definition: Some(Arc::new(def)),
        assistant_identity_prefix: args.assistant_identity_prefix.clone(),
        mcp_resolver: mcp_resolver_for_cwd(args),
    }
}

/// Scheduler-only goal control worker. These roles cannot be resolved from
/// agent files or selected by a model. The evaluator has no tools; the other
/// roles receive only Cockpit's path-contained read primitive.
pub fn goal_control(
    role: crate::engine::schedule::authority::SpawnWorkerKind,
    args: &SpawnArgs,
) -> Agent {
    let mut def = crate::agents::embedded_internal_default("standard")
        .expect("standard has an internal agent definition");
    use crate::engine::schedule::authority::SpawnWorkerKind;
    let (name, system, tools) = match role {
        SpawnWorkerKind::GoalPlanner => (
            "goal-planner",
            "You are the host goal contract planner. Investigate read-only and return only the requested strict JSON contract. State observable outcomes, not file prescriptions.",
            ToolBox::new().with(Arc::new(crate::tools::read::ReadTool)),
        ),
        SpawnWorkerKind::GoalEvaluator => (
            "goal-evaluator",
            "You are the host goal evaluator. You have no tools. Return only the requested strict JSON decision from supplied evidence.",
            ToolBox::new(),
        ),
        SpawnWorkerKind::GoalGatekeeper => (
            "goal-gatekeeper",
            "You are a resumed gap gatekeeper. Recheck only prior unresolved gaps. Uncertainty refutes. Return only strict JSON.",
            ToolBox::new().with(Arc::new(crate::tools::read::ReadTool)),
        ),
        SpawnWorkerKind::GoalColdSkeptic => (
            "goal-cold-skeptic",
            "You are an independent cold completion skeptic. Try to refute the immutable contract from evidence. Uncertainty refutes. Return only strict JSON.",
            ToolBox::new().with(Arc::new(crate::tools::read::ReadTool)),
        ),
        SpawnWorkerKind::Bee | SpawnWorkerKind::Scout => {
            unreachable!("ordinary swarm workers are built by their dedicated factories")
        }
    };
    def.name = name.to_string();
    def.prompt = system.to_string();
    def.prompt_overrides.clear();
    let model = resolve_agent_model(&def, args)
        .expect("goal-control worker resolves a conversational model");
    Agent {
        name: name.to_string(),
        system: compose_system_prompt_for_model(system, &model, args),
        role_prompt: system.to_string(),
        tools,
        // Scheduler-only goal workers inherit the parent's host-chosen model
        // (no selector), so posture resolves from that model's own config.
        tool_steering: crate::agents::ToolSteering::from_def(&def),
        posture: crate::agents::PostureResolution::from_def(&def),
        model,
        params: args.params.clone(),
        scan_tool_results: true,
        context_policy: def.context_policy.clone(),
        lock_identity: name.to_string(),
        write_scope: None,
        delegated: true,
        delegation_recursion: DelegationRecursionContext {
            enabled: false,
            remaining_depth: 0,
            allowed_targets: Vec::new(),
            same_model_only: true,
        },
        vnext_grant: None,
        env_overlay: args.env_overlay.clone(),
        definition: Some(Arc::new(def)),
        assistant_identity_prefix: args.assistant_identity_prefix.clone(),
        mcp_resolver: mcp_resolver_for_cwd(args),
    }
}

/// `Plan` — the user-facing read-only planning agent. It investigates the
/// project, keeps a session-scoped virtual plan document, and hands the final
/// standalone plan to a fresh `Build` session when the user agrees. It holds no
/// filesystem write or lock tools.
pub fn plan(args: &SpawnArgs) -> Agent {
    let def = crate::agents::embedded_default("Plan").expect("Plan has an embedded definition");
    let base_tools = with_lsp_nav(with_build_family_intel(
        ToolBox::new()
            .with(Arc::new(crate::tools::read::ReadTool))
            .with(Arc::new(crate::tools::bash::BashTool::new())),
    ))
    .with(Arc::new(crate::tools::plan_doc::PlanReadTool))
    .with(Arc::new(crate::tools::plan_doc::PlanWriteTool))
    .with(Arc::new(crate::tools::plan_doc::PlanEditTool))
    .with(Arc::new(crate::tools::plan_doc::StartBuildTool))
    .with(Arc::new(crate::tools::question::QuestionTool))
    .with(Arc::new(crate::tools::skill::SkillTool))
    .with(Arc::new(crate::tools::harness::HarnessListTool))
    .with(Arc::new(crate::tools::harness::HarnessInvokeTool))
    .with(Arc::new(crate::tools::mcp_tool::McpTool));
    let tools = with_recall_tools(
        with_custom_tools(
            with_task_for_targets(base_tools, args, &["explore"]),
            &args.config,
            &args.cwd,
            &std::collections::BTreeSet::new(),
        ),
        args,
    );

    let model = resolve_agent_model(&def, args)
        .expect("Plan embedded definition resolves a conversational model");
    let tool_steering = crate::agents::ToolSteering::from_def(&def);
    let posture = crate::agents::PostureResolution::from_def(&def);
    let role = PLAN_PROMPT;
    Agent {
        name: "Plan".to_string(),
        system: compose_system_prompt_for_model(role, &model, args),
        role_prompt: role.to_string(),
        tools,
        model,
        params: args.params.clone(),
        scan_tool_results: true,
        tool_steering,
        posture,
        context_policy: def.context_policy.clone(),
        lock_identity: args
            .lock_identity
            .clone()
            .unwrap_or_else(|| "Plan".to_string()),
        write_scope: args.write_scope.clone(),
        delegated: args.delegated,
        delegation_recursion: args.delegation_recursion.clone(),
        vnext_grant: args.vnext_grant.clone(),
        env_overlay: args.env_overlay.clone(),
        definition: Some(Arc::new(def)),
        assistant_identity_prefix: args.assistant_identity_prefix.clone(),
        mcp_resolver: mcp_resolver_for_cwd(args),
    }
}

/// `Multireview` — hidden read-only primary reached only by `/multireview`.
/// Orchestrates `scout` fan-out and isolated harness reviewers, then returns a
/// single consolidated analysis. No write/lock tools.
pub fn multireview(args: &SpawnArgs) -> Agent {
    let def = crate::agents::embedded_default("Multireview")
        .expect("Multireview has an embedded definition");
    let tools = with_recall_tools(
        with_custom_tools(
            with_full_intel(
                ToolBox::new()
                    .with(Arc::new(crate::tools::read::ReadTool))
                    .with(Arc::new(crate::tools::bash::BashTool::new())),
            )
            .with(Arc::new(crate::tools::spawn::SpawnTool::for_depth(
                args.swarm_depth,
                args.swarm_max_depth,
            )))
            .with(Arc::new(crate::tools::harness::HarnessListTool))
            .with(Arc::new(crate::tools::harness::HarnessInvokeTool))
            .with(Arc::new(crate::tools::schedule::ScheduleTool))
            .with(Arc::new(crate::tools::question::QuestionTool))
            .with(Arc::new(crate::tools::mcp_tool::McpTool)),
            &args.config,
            &args.cwd,
            &std::collections::BTreeSet::new(),
        ),
        args,
    );

    let model = resolve_agent_model(&def, args)
        .expect("Multireview embedded definition resolves a conversational model");
    let tool_steering = crate::agents::ToolSteering::from_def(&def);
    let posture = crate::agents::PostureResolution::from_def(&def);
    let role = MULTIREVIEW_PROMPT;
    Agent {
        name: "Multireview".to_string(),
        system: compose_system_prompt_for_model(role, &model, args),
        role_prompt: role.to_string(),
        tools,
        model,
        params: args.params.clone(),
        scan_tool_results: true,
        tool_steering,
        posture,
        context_policy: def.context_policy.clone(),
        lock_identity: args
            .lock_identity
            .clone()
            .unwrap_or_else(|| "Multireview".to_string()),
        write_scope: args.write_scope.clone(),
        delegated: args.delegated,
        delegation_recursion: args.delegation_recursion.clone(),
        vnext_grant: args.vnext_grant.clone(),
        env_overlay: args.env_overlay.clone(),
        definition: Some(Arc::new(def)),
        assistant_identity_prefix: args.assistant_identity_prefix.clone(),
        mcp_resolver: mcp_resolver_for_cwd(args),
    }
}

/// `bee` — `Swarm`'s recursive parallel **worker** (GOALS §24/§26).
/// NONINTERACTIVE: spawned in parallel in the background by `spawn` (from the
/// `Swarm` primary or a deeper `bee`), it never blocks on the user — the parent
/// authors its focused brief up front. WRITE-CAPABLE: its surface mirrors
/// `builder`'s (read/bash/full intel/skill/web + the lock/write tools +
/// `task→docs`), plus the recursive `spawn` tool. Its writes go through the
/// **single lock authority** (`crate::locks`, keyed by `(session, agent)`):
/// disjoint scopes run in parallel, a same-path write is serialized/rejected.
/// It has **no base MCP/browser** — those are granted per-task by its parent
/// (implementation note). It finishes via the structured-return
/// envelope (`return`). The recursive-spawn description carries the per-task
/// effective depth (`args.swarm_depth`) + ceiling so the model self-limits;
/// a spawn over the ceiling is refused and the branch does the slice itself.
pub fn bee(args: &SpawnArgs) -> Agent {
    let def = crate::agents::embedded_default("bee").expect("bee has an embedded definition");
    let recursive_targets = recursive_targets(&args.config, &["docs"]);
    let recursive_refs: Vec<&str> = recursive_targets.iter().map(String::as_str).collect();
    let base_tools = with_write_tools(with_full_intel(
        ToolBox::new()
            .with(Arc::new(crate::tools::read::ReadTool))
            .with(Arc::new(crate::tools::bash::BashTool::new())),
    ))
    // `skill` (GOALS §5): manual on-demand skill loading.
    .with(Arc::new(crate::tools::skill::SkillTool));
    let tools = with_recall_tools(
        with_custom_tools(
            with_task_for_targets(base_tools, args, &recursive_refs)
                // The recursive fan-out tool (GOALS §24): a `bee` may fan out
                // deeper `bee` workers, routed back to the single async-job
                // authority. Holds no base MCP — parent-granted per task.
                .with(Arc::new(crate::tools::spawn::SpawnTool::for_depth(
                    args.swarm_depth,
                    args.swarm_max_depth,
                ))),
            &args.config,
            &args.cwd,
            &std::collections::BTreeSet::new(),
        ),
        args,
    );
    // `return` (structured-summary envelope): `bee` is a delegated worker, so it
    // finishes by reporting a compact structured summary (+ a pointer to its
    // dedicated output) up to its parent.
    let tools = with_return_tool(tools, "bee");

    let model = resolve_agent_model(&def, args)
        .expect("bee embedded definition resolves a conversational model");
    let tool_steering = crate::agents::ToolSteering::from_def(&def);
    let posture = crate::agents::PostureResolution::from_def(&def);
    let role = BEE_PROMPT;
    Agent {
        name: "bee".to_string(),
        system: compose_system_prompt_for_model(role, &model, args),
        role_prompt: role.to_string(),
        tools,
        model,
        params: args.params.clone(),
        scan_tool_results: true,
        tool_steering,
        posture,
        context_policy: def.context_policy.clone(),
        lock_identity: args
            .lock_identity
            .clone()
            .unwrap_or_else(|| "bee".to_string()),
        write_scope: args.write_scope.clone(),
        delegated: args.delegated,
        delegation_recursion: args.delegation_recursion.clone(),
        vnext_grant: args.vnext_grant.clone(),
        env_overlay: args.env_overlay.clone(),
        definition: Some(Arc::new(def)),
        assistant_identity_prefix: args.assistant_identity_prefix.clone(),
        mcp_resolver: mcp_resolver_for_cwd(args),
    }
}

/// Docs.1 — the resolver stage of the `docs` pipeline. Runs in the
/// caller's cwd (same trust level as `explore`/`builder`), gated to the
/// registry tools plus `bash`/`webfetch`/`websearch` for registry
/// lookups. Receives **only** the package name (the question never
/// enters its context — token economy, GOALS §10). `resolution` is the
/// shared slot the pipeline reads to learn which package dir to launch
/// Docs.2 in; `target` is the package the caller asked about.
pub fn docs_resolver(
    args: &SpawnArgs,
    resolution: std::sync::Arc<crate::tools::docs::DocsResolution>,
    target: String,
    approver: Option<Arc<crate::approval::Approver>>,
    interrupts: Option<Arc<crate::engine::interrupt::InterruptHub>>,
) -> Result<Agent> {
    let def = crate::agents::embedded_internal_default("docs-resolver")
        .expect("docs-resolver has an internal agent definition");
    // FAIL CLOSED on an unresolvable docs-resolver model (e.g. a config refresh
    // after the docs preflight made the stage model unresolvable): propagate the
    // content-safe error to the pipeline caller rather than panic mid-pipeline.
    let mut agent = agent_from_def(&def, args)?;
    agent.tools = agent
        .tools
        .with(Arc::new(crate::tools::docs::ListPackagesTool::new(
            resolution.clone(),
            target,
        )))
        // The package-add gate's approver + interrupt hub are threaded
        // straight into the tool — independent of the noninteractive
        // `ToolCtx::approver` the pipeline leaves `None` (so the
        // filesystem-confine path raises no escalation), per
        // implementation note.
        .with(Arc::new(crate::tools::docs::AddPackageTool::new(
            resolution, approver, interrupts,
        )));
    Ok(agent)
}

/// Docs.2 — the answerer stage of the `docs` pipeline. Runs in the
/// resolved package directory (`args.cwd` is the package root). Tools:
/// `read` + the sandboxed `grep`/`glob` only — **no bash, no network, no
/// write** (prompt `docs-agent.md` decision 2/3). The sandbox confines
/// every path to `args.cwd`, which is why bash can be denied: Docs.2 runs
/// inside untrusted third-party source.
pub fn docs_answerer(args: &SpawnArgs) -> Result<Agent> {
    let def = crate::agents::embedded_internal_default("docs-answerer")
        .expect("docs-answerer has an internal agent definition");
    // FAIL CLOSED on an unresolvable docs-answerer model rather than panic
    // mid-pipeline; the pipeline caller returns the content-safe routing error.
    agent_from_def(&def, args)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::extended::ExtendedConfig;
    use crate::engine::tool::Tool;

    /// F3. Computer use ships desktop screenshots — a potentially sensitive
    /// payload — so its route is custody-typed. Custody is the configured
    /// computer-use model's own trust class (host-authorized: enabling
    /// `computer_use` on a model is a host configuration decision), and a model
    /// that cannot satisfy the typed request is not offered as a candidate.
    #[test]
    fn computer_use_route_is_custody_typed() {
        use crate::config::providers::{
            CapabilityStatus, ComputerUseCapability, ComputerUseContract, ModelCapabilities,
            ModelEntry, ModelTrust, ProviderEntry, ProvidersConfig,
        };

        let vision_model = |id: &str, trust: ModelTrust, invokable: bool| ModelEntry {
            id: id.to_string(),
            subagent_invokable: Some(invokable),
            trust: Some(trust),
            capabilities: ModelCapabilities {
                image_input: CapabilityStatus::Supported,
                computer_use: ComputerUseCapability {
                    contract: Some(ComputerUseContract::Anthropic20251124),
                    source: None,
                },
                ..ModelCapabilities::default()
            },
            ..ModelEntry::default()
        };

        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "selfhosted".into(),
            ProviderEntry {
                url: "http://localhost:1/v1".into(),
                models: vec![vision_model("vision", ModelTrust::Trusted, true)],
                ..ProviderEntry::default()
            },
        );
        cfg.providers.insert(
            "cloud".into(),
            ProviderEntry {
                url: "http://localhost:2/v1".into(),
                models: vec![vision_model("vision", ModelTrust::Untrusted, true)],
                ..ProviderEntry::default()
            },
        );

        // The trusted (self-hosted) model is eligible under trusted custody.
        // The eligibility API mints no grant and takes no payload, so this
        // decision can never release or render anything.
        let trusted = computer_use_custody_route(&cfg, "selfhosted", "vision")
            .expect("a trusted computer-use model routes");
        assert_eq!(trusted.trust, ModelTrust::Trusted);
        assert_eq!(
            trusted.custody_filter,
            Some(crate::config::providers::ModelCustody::Trusted)
        );

        // The untrusted (cloud) model is eligible under untrusted custody.
        let untrusted = computer_use_custody_route(&cfg, "cloud", "vision")
            .expect("an untrusted computer-use model routes");
        assert_eq!(untrusted.trust, ModelTrust::Untrusted);
        assert_eq!(
            untrusted.custody_filter,
            Some(crate::config::providers::ModelCustody::Untrusted)
        );

        // A model that cannot satisfy the typed request is refused, so
        // `computer_subagent_candidate` never offers it.
        cfg.providers.insert(
            "hidden".into(),
            ProviderEntry {
                url: "http://localhost:3/v1".into(),
                models: vec![vision_model("vision", ModelTrust::Untrusted, false)],
                ..ProviderEntry::default()
            },
        );
        assert!(
            computer_use_custody_route(&cfg, "hidden", "vision").is_err(),
            "a non-subagent-invokable model must not be routable for computer use"
        );

        // A model with no vision capability is refused by the same request.
        cfg.providers.insert(
            "blind".into(),
            ProviderEntry {
                url: "http://localhost:4/v1".into(),
                models: vec![ModelEntry {
                    id: "text".into(),
                    subagent_invokable: Some(true),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
        assert!(computer_use_custody_route(&cfg, "blind", "text").is_err());
    }

    /// A keyless localhost model + [`SpawnArgs`] for exercising the agent
    /// factories. The model is never actually called — these tests only
    /// inspect the constructed agent's name + tool surface.
    fn test_spawn_args(cwd: &Path) -> SpawnArgs {
        test_spawn_args_with_provider_can_delegate(cwd, None)
    }

    /// Give a vNext definition the same host-resolved grant a daemon-owned
    /// session would carry.  Tests that inspect `task` must opt into this
    /// explicit authority path: merely loading a manifest deliberately does
    /// not project legacy task authority onto it.
    fn test_spawn_args_with_vnext_grant(cwd: &Path, name: &str) -> SpawnArgs {
        let mut args = test_spawn_args(cwd);
        let host = Arc::new(crate::agents::VnextHostPolicy::for_session_config(
            &args.config.extended(),
        ));
        let definition = crate::agents::embedded_default(name)
            .unwrap_or_else(|| panic!("missing embedded vNext definition `{name}`"));
        args.vnext_grant = Some(
            definition
                .vnext
                .as_ref()
                .unwrap_or_else(|| panic!("embedded `{name}` must have a vNext declaration"))
                .resolve_grant(&host)
                .unwrap_or_else(|err| panic!("embedded `{name}` vNext grant must resolve: {err}")),
        );
        args.vnext_host_policy = Some(host);
        args
    }

    fn test_assistant_db() -> crate::db::Db {
        crate::db::Db::open_in_memory().unwrap()
    }

    fn trusted_policy(cwd: &Path) -> crate::config::trust::WorkspaceTrustPolicy {
        crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(cwd).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        }
    }

    async fn unknown_agent_rejection_for_test(
        cwd: &Path,
        config: &crate::daemon::session_worker::SessionConfigHandle,
        parent_agent: &str,
        requested_agent: &str,
        db: &crate::db::Db,
    ) -> Option<String> {
        crate::config::trust::scope_workspace_trust_policy(
            trusted_policy(cwd),
            unknown_agent_rejection(cwd, config, parent_agent, requested_agent, db),
        )
        .await
    }

    fn test_spawn_args_with_provider_can_delegate(
        cwd: &Path,
        can_delegate: Option<bool>,
    ) -> SpawnArgs {
        let _trust = crate::config::trust::enter_workspace_trust_policy(trusted_policy(cwd));
        use crate::config::providers::{ActiveModelRef, ProviderEntry, ProvidersConfig};
        use std::collections::BTreeMap;
        let mut providers = BTreeMap::new();
        providers.insert(
            "lmstudio".to_string(),
            ProviderEntry {
                url: "http://localhost:1/v1".into(),
                headers: vec![],
                can_delegate,
                ..ProviderEntry::default()
            },
        );
        let pcfg = ProvidersConfig {
            providers,
            active_model: Some(ActiveModelRef {
                provider: "lmstudio".into(),
                model: "local".into(),
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            }),
            ..ProvidersConfig::default()
        };
        let model = Arc::new(
            crate::engine::model::Model::from_config(
                &pcfg,
                std::sync::Arc::new(crate::redact::RedactionTable::empty()),
            )
            .unwrap(),
        );
        SpawnArgs {
            model,
            params: ModelParams::default(),
            env_overlay: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            cwd: cwd.to_path_buf(),
            config: crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(cwd),
            session_short_id: String::new(),
            assistant_identity_prefix: None,
            model_system_prompt_snapshot: Arc::new(ModelSystemPromptSnapshot::empty()),
            interactive: true,
            model_override: None,
            delegation_model: None,
            delegated: false,
            delegation_recursion: DelegationRecursionContext::default(),
            vnext_grant: None,
            vnext_host_policy: None,
            vnext_local_installation_resolver:
                crate::agents::LocalInstallationResolver::no_installations(),
            parent_vnext_grant: None,
            parent_posture: None,
            swarm_depth: 0,
            swarm_max_depth: crate::config::extended::DEFAULT_RECURSIVE_SPAWN_MAX_DEPTH,
            granted_tools: Vec::new(),
            lock_identity: None,
            write_scope: None,
            credential_store: None,
        }
    }

    fn sorted_tool_names(agent: &Agent) -> Vec<String> {
        let mut names: Vec<String> = agent
            .tools
            .names()
            .into_iter()
            .map(str::to_string)
            .collect();
        names.sort();
        names
    }

    #[test]
    fn build_skill_manage_tool_set_includes_skill_manage() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        let names = sorted_tool_names(&build(&args));
        assert!(names.iter().any(|name| name == "skill_manage"));
    }

    fn host_for_agent(agent: &Agent, cwd: &Path) -> crate::mcp::builtin::HostContext {
        let mut ctx = crate::tools::common::test_ctx(cwd);
        ctx.mcp_builtin_registry = agent.tools.mcp_builtin_registry();
        crate::mcp::builtin::HostContext::from_tool_ctx(&ctx)
    }

    #[test]
    fn builtin_agent_grant_equivalence_to_embedded_defs() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());

        for &name in crate::agents::BUILTIN_AGENT_NAMES {
            let loaded = load(name, &args).unwrap();
            let def = crate::agents::embedded_default(name).unwrap();
            let expected = agent_from_def(&def, &args).unwrap();
            assert_eq!(
                sorted_tool_names(&loaded),
                sorted_tool_names(&expected),
                "{name} loaded from AgentDef must match embedded construction"
            );
        }
    }

    #[test]
    fn loaded_builder_has_defer_to_orchestrator() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        let agent = load("builder", &args).unwrap();

        assert!(agent.tools.names().contains(&"defer_to_orchestrator"));
    }

    #[test]
    fn loaded_explore_has_defer_to_orchestrator() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        let agent = load("explore", &args).unwrap();

        assert!(agent.tools.names().contains(&"defer_to_orchestrator"));
    }

    #[test]
    fn history_agent_def_is_read_only_leaf_with_builtin_history_tools() {
        use crate::agents::{AgentMode, ToolTier};

        let def = crate::agents::embedded_default("history").expect("history embedded default");
        assert_eq!(def.name, "history");
        assert_eq!(def.mode, AgentMode::Subagent);

        let tools = def.tools.as_ref().expect("history has explicit tools");
        for tool in [
            "read",
            "session_search",
            "session_read",
            "session_lineage_search",
        ] {
            assert!(tools.iter().any(|name| name == tool), "{tool} missing");
        }
        for forbidden in [
            "task", "spawn", "handoff", "bash", "write", "edit", "unlock",
        ] {
            assert!(
                !tools.iter().any(|name| name == forbidden),
                "{forbidden} must not be on history"
            );
        }
        for tool in ["session_search", "session_read", "session_lineage_search"] {
            assert_eq!(def.tool_tiers.get(tool), Some(&ToolTier::Enabled));
        }
        crate::agents::validate_invariants(&def).expect("history def is invariant-valid");
    }

    #[test]
    fn history_agent_has_first_class_history_tools_and_short_report_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        let agent = load("history", &args).unwrap();
        let names = agent.tools.names();

        for tool in ["session_search", "session_read", "session_lineage_search"] {
            assert!(
                names.contains(&tool),
                "{tool} should be a first-class history tool: {names:?}"
            );
        }
        assert!(!names.contains(&"task"), "history must remain a leaf");
        assert!(
            agent.role_prompt.contains("Return a short report")
                || agent.role_prompt.contains("return only the useful excerpt"),
            "history prompt must bound the task result"
        );
        assert!(
            agent.role_prompt.contains("Do not paste raw transcripts")
                || agent.role_prompt.contains("avoid dumping transcripts"),
            "history prompt must forbid raw transcript dumps"
        );
    }

    #[test]
    fn bundled_agents_without_defer_to_orchestrator_stay_without_it() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());

        for name in [
            "history",
            "bee",
            "scout",
            "deepthink",
            "Build",
            "Careful",
            "Plan",
        ] {
            let agent = load(name, &args).unwrap();
            assert!(
                !agent.tools.names().contains(&"defer_to_orchestrator"),
                "{name} must not carry defer_to_orchestrator"
            );
        }
    }

    #[test]
    fn defer_to_orchestrator_is_last_in_builder_and_explore_defs() {
        for name in ["builder", "explore"] {
            let def = crate::agents::embedded_default(name).unwrap();
            let tools = def.tools.as_ref().expect("built-in def has tools");

            assert_eq!(
                tools.last().map(String::as_str),
                Some("defer_to_orchestrator"),
                "{name} must append defer_to_orchestrator last"
            );
        }
    }

    #[test]
    fn factory_and_def_tool_surfaces_agree_for_builder_and_explore() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());

        for (name, factory) in [
            ("builder", builder as fn(&SpawnArgs) -> Agent),
            ("explore", explore as fn(&SpawnArgs) -> Agent),
            ("history", history as fn(&SpawnArgs) -> Agent),
        ] {
            let loaded = load(name, &args).unwrap();
            let factory_agent = factory(&args);

            assert_eq!(
                sorted_tool_names(&loaded),
                sorted_tool_names(&factory_agent),
                "{name} factory and AgentDef surfaces must agree"
            );
        }
    }

    #[test]
    fn builtin_agent_grant_internal_defs_exist_and_construct() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());

        for name in ["computer", "docs-resolver", "docs-answerer"] {
            assert!(
                crate::agents::embedded_internal_default(name).is_some(),
                "{name} must have an internal AgentDef"
            );
        }

        let resolution = crate::tools::docs::DocsResolution::new();
        let resolver = docs_resolver(&args, resolution, "pkg".to_string(), None, None).unwrap();
        assert_eq!(
            sorted_tool_names(&resolver),
            vec![
                "add-package",
                "bash",
                "list-packages",
                "webfetch",
                "websearch"
            ]
        );

        let answerer = docs_answerer(&args).unwrap();
        assert_eq!(sorted_tool_names(&answerer), vec!["glob", "grep", "read"]);
    }

    #[test]
    fn builtin_agent_grant_graph_is_grantable_and_on_explore() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        let def = crate::agents::AgentDef {
            name: "graph-user".to_string(),
            description: "custom".to_string(),
            mode: crate::agents::AgentMode::Subagent,
            model: None,
            temperature: None,
            tools: Some(vec!["graph".to_string()]),
            tool_tiers: std::collections::BTreeMap::new(),
            tool_descriptions: std::collections::BTreeMap::new(),
            scan_tool_results: None,
            goal_supervision: crate::agents::GoalSettingsOverride::default(),
            permission: None,
            capabilities: None,
            tool_steering: None,
            context_policy: None,
            vnext: None,
            prompt: "body".to_string(),
            prompt_overrides: std::collections::BTreeMap::new(),
            package_files: None,
            private_subagents: std::collections::BTreeMap::new(),
            source: tmp.path().join("graph-user.md"),
        };

        crate::agents::validate_invariants(&def).expect("graph is a known grantable tool");
        let agent = agent_from_def(&def, &args).expect("graph materializes");

        assert!(agent.tools.names().contains(&"graph"));
        assert!(
            crate::mcp::builtin::describe(
                &host_for_agent(&load("explore", &args).unwrap(), tmp.path()),
                "graph"
            )
            .is_ok()
        );
    }

    #[test]
    fn tool_tier_enabled_discoverable_disabled_place_tools_and_catalog_entries() {
        use crate::agents::{AgentDef, AgentMode, ToolTier};
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        let mut tool_tiers = std::collections::BTreeMap::new();
        tool_tiers.insert("code".to_string(), ToolTier::Discoverable);
        tool_tiers.insert("search".to_string(), ToolTier::Disabled);
        let def = AgentDef {
            name: "custom-tiered".to_string(),
            description: "custom".to_string(),
            mode: AgentMode::Primary,
            model: None,
            temperature: None,
            tools: Some(vec![
                "read".to_string(),
                "code".to_string(),
                "search".to_string(),
                "mcp".to_string(),
            ]),
            tool_tiers,
            tool_descriptions: std::collections::BTreeMap::new(),
            scan_tool_results: Some(true),
            goal_supervision: crate::agents::GoalSettingsOverride::default(),
            permission: None,
            capabilities: None,
            tool_steering: None,
            context_policy: None,
            vnext: None,
            prompt: "body".to_string(),
            prompt_overrides: std::collections::BTreeMap::new(),
            package_files: None,
            private_subagents: std::collections::BTreeMap::new(),
            source: tmp.path().join("custom-tiered.md"),
        };
        let agent = agent_from_def(&def, &args).unwrap();
        let names = agent.tools.names();
        assert!(names.contains(&"read"), "{names:?}");
        assert!(!names.contains(&"code"), "{names:?}");
        assert!(!names.contains(&"search"), "{names:?}");

        let host = host_for_agent(&agent, tmp.path());
        assert!(
            crate::mcp::builtin::describe(&host, "read")
                .unwrap()
                .description
                .contains("direct builtin tool")
        );
        assert!(
            crate::mcp::builtin::search(&host, "read")
                .iter()
                .any(|hit| hit.tool == "read")
        );
        assert!(
            !crate::mcp::builtin::describe(&host, "code")
                .unwrap()
                .description
                .contains("direct builtin tool")
        );
        assert!(crate::mcp::builtin::describe(&host, "search").is_err());
        assert!(
            crate::mcp::builtin::search(&host, "code")
                .iter()
                .any(|hit| hit.tool == "code")
        );
        assert!(
            crate::mcp::builtin::search(&host, "search")
                .iter()
                .all(|hit| hit.tool != "search")
        );
    }

    #[tokio::test]
    async fn enabled_tier_tools_reachable_via_monty() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("sample.txt"), "hello from mcp\n").unwrap();
        let agent = default_build(&test_spawn_args(tmp.path()));
        let host = host_for_agent(&agent, tmp.path());

        assert!(agent.tools.names().contains(&"read"));
        assert!(
            crate::mcp::builtin::search(&host, "read")
                .iter()
                .any(|hit| hit.tool == "read")
        );
        let out = crate::mcp::sandbox::run_with_host(
            "mcp.invoke('cockpit', 'read', {'path': 'sample.txt'})",
            &crate::mcp::config::McpConfig::default(),
            &host,
        )
        .await
        .unwrap();

        assert!(out.contains("hello from mcp"), "{out}");
    }

    #[test]
    fn tool_tier_structural_tools_including_defer_to_orchestrator_are_absent_from_monty_registry() {
        let tmp = tempfile::tempdir().unwrap();
        let agent = build(&test_spawn_args(tmp.path()));
        let host = host_for_agent(&agent, tmp.path());
        for tool in [
            "question",
            "return",
            "schedule",
            "task",
            "spawn",
            "defer_to_orchestrator",
            "start_build",
        ] {
            assert!(
                crate::mcp::builtin::describe(&host, tool).is_err(),
                "{tool} must not be served through monty"
            );
        }
    }

    #[test]
    fn tool_tier_disabled_custom_bash_tool_is_filtered() {
        use crate::agents::{AgentDef, AgentMode, ToolTier};
        let tmp = tempfile::tempdir().unwrap();
        let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        write_project_config(
            tmp.path(),
            r#"{
                "tools": {
                    "my_tool": {
                        "enabled": true,
                        "command": "echo {value}"
                    }
                }
            }"#,
        );
        let mut tool_tiers = std::collections::BTreeMap::new();
        tool_tiers.insert("my_tool".to_string(), ToolTier::Disabled);
        let def = AgentDef {
            name: "custom-with-disabled-tool".to_string(),
            description: "custom".to_string(),
            mode: AgentMode::Primary,
            model: None,
            temperature: None,
            tools: None,
            tool_tiers,
            tool_descriptions: std::collections::BTreeMap::new(),
            scan_tool_results: Some(true),
            goal_supervision: crate::agents::GoalSettingsOverride::default(),
            permission: None,
            capabilities: None,
            tool_steering: None,
            context_policy: None,
            vnext: None,
            prompt: "body".to_string(),
            prompt_overrides: std::collections::BTreeMap::new(),
            package_files: None,
            private_subagents: std::collections::BTreeMap::new(),
            source: tmp.path().join("custom-with-disabled-tool.md"),
        };

        let agent = agent_from_def(&def, &test_spawn_args(tmp.path())).unwrap();
        let names = agent.tools.names();
        assert!(!names.contains(&"my_tool"), "{names:?}");
    }

    #[test]
    fn tool_tier_stock_build_defaults_move_tail_to_monty() {
        let tmp = tempfile::tempdir().unwrap();
        let agent = default_build(&test_spawn_args(tmp.path()));
        let names = agent.tools.names();
        let host = host_for_agent(&agent, tmp.path());

        for tool in [
            "graph",
            "change_impact",
            "harness_list",
            "harness_invoke",
            "session_search",
            "session_read",
            "session_lineage_search",
        ] {
            assert!(
                !names.contains(&tool),
                "{tool} should not be directly injected"
            );
            assert!(
                crate::mcp::builtin::describe(&host, tool).is_ok(),
                "{tool} should be discoverable through monty"
            );
        }

        for tool in [
            "read",
            "bash",
            "write",
            "edit",
            "unlock",
            "search",
            "code",
            "context_pack",
            "todo",
        ] {
            assert!(names.contains(&tool), "{tool} should be directly injected");
        }
    }

    #[test]
    fn hardcoded_build_family_factories_keep_graph_tail_discoverable() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());

        for (name, agent) in [("Build", build(&args)), ("Plan", plan(&args))] {
            let names = agent.tools.names();
            let host = host_for_agent(&agent, tmp.path());

            for tool in ["graph", "change_impact"] {
                assert!(
                    !names.contains(&tool),
                    "`{name}` should not directly inject `{tool}`"
                );
                assert!(
                    crate::mcp::builtin::describe(&host, tool).is_ok(),
                    "`{name}` should expose `{tool}` through monty"
                );
            }
            for tool in ["context_pack", "code", "search"] {
                assert!(
                    names.contains(&tool),
                    "`{name}` should directly inject `{tool}`"
                );
            }
        }
    }

    #[test]
    fn intel_default_tiers_are_graph_and_change_impact() {
        use crate::agents::{AgentDef, AgentMode, ToolTier};

        let tmp = tempfile::tempdir().unwrap();
        let def = AgentDef {
            name: "Build".to_string(),
            description: "build".to_string(),
            mode: AgentMode::Primary,
            model: None,
            temperature: None,
            tools: None,
            tool_tiers: std::collections::BTreeMap::new(),
            tool_descriptions: std::collections::BTreeMap::new(),
            scan_tool_results: None,
            goal_supervision: crate::agents::GoalSettingsOverride::default(),
            permission: None,
            capabilities: None,
            tool_steering: None,
            context_policy: None,
            vnext: None,
            prompt: "body".to_string(),
            prompt_overrides: std::collections::BTreeMap::new(),
            package_files: None,
            private_subagents: std::collections::BTreeMap::new(),
            source: tmp.path().join("Build.md"),
        };

        for tool in ["graph", "change_impact"] {
            assert_eq!(
                effective_tool_tier(&def, tool, false),
                ToolTier::Discoverable
            );
        }
        for tool in ["search", "code", "context_pack"] {
            assert_eq!(effective_tool_tier(&def, tool, false), ToolTier::Enabled);
        }
        for removed in ["deps", "circular", "impact", "hot"] {
            assert!(
                !default_discoverable_tools_for("Build").contains(&removed),
                "{removed} should not be a default discoverable tool"
            );
        }
    }

    #[test]
    fn tool_tier_lsp_and_skill_manage_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        let explore_agent = load("explore", &args).unwrap();
        let build_agent = default_build(&args);

        assert!(explore_agent.tools.names().contains(&"lsp"));
        assert!(!build_agent.tools.names().contains(&"lsp"));
        assert!(
            crate::mcp::builtin::describe(&host_for_agent(&build_agent, tmp.path()), "lsp").is_ok()
        );
        assert!(!build_agent.tools.names().contains(&"skill_manage"));
    }

    #[test]
    fn tool_tier_assistant_defaults_make_episodic_tools_discoverable() {
        use crate::agents::{AgentDef, AgentMode};
        let tmp = tempfile::tempdir().unwrap();
        let mut args = test_spawn_args(tmp.path());
        args.assistant_identity_prefix = Some("assistant identity".to_string());
        let def = AgentDef {
            name: "helper".to_string(),
            description: "assistant".to_string(),
            mode: AgentMode::Primary,
            model: None,
            temperature: None,
            tools: None,
            tool_tiers: std::collections::BTreeMap::new(),
            tool_descriptions: std::collections::BTreeMap::new(),
            scan_tool_results: Some(true),
            goal_supervision: crate::agents::GoalSettingsOverride::default(),
            permission: None,
            capabilities: None,
            tool_steering: None,
            context_policy: None,
            vnext: None,
            prompt: "body".to_string(),
            prompt_overrides: std::collections::BTreeMap::new(),
            package_files: None,
            private_subagents: std::collections::BTreeMap::new(),
            source: tmp.path().join("helper.md"),
        };

        let agent = agent_from_def(&def, &args).unwrap();
        let names = agent.tools.names();
        assert!(names.contains(&"skill_manage"), "{names:?}");
        assert!(names.contains(&"mcp"), "{names:?}");
        let host = host_for_agent(&agent, tmp.path());
        for tool in ["session_search", "session_read", "session_lineage_search"] {
            assert!(
                !names.contains(&tool),
                "{tool} should not be directly injected"
            );
            assert!(crate::mcp::builtin::describe(&host, tool).is_ok());
        }
    }

    #[test]
    fn assistant_discoverable_recall_tools_are_reachable_via_mcp() {
        use crate::agents::{AgentDef, AgentMode};
        let tmp = tempfile::tempdir().unwrap();
        let mut args = test_spawn_args(tmp.path());
        args.assistant_identity_prefix = Some("assistant identity".to_string());
        let def = AgentDef {
            name: "helper".to_string(),
            description: "assistant".to_string(),
            mode: AgentMode::Primary,
            model: None,
            temperature: None,
            tools: None,
            tool_tiers: std::collections::BTreeMap::new(),
            tool_descriptions: std::collections::BTreeMap::new(),
            scan_tool_results: Some(true),
            goal_supervision: crate::agents::GoalSettingsOverride::default(),
            permission: None,
            capabilities: None,
            tool_steering: None,
            context_policy: None,
            vnext: None,
            prompt: "body".to_string(),
            prompt_overrides: std::collections::BTreeMap::new(),
            package_files: None,
            private_subagents: std::collections::BTreeMap::new(),
            source: tmp.path().join("helper.md"),
        };

        let agent = agent_from_def(&def, &args).unwrap();
        let names = agent.tools.names();
        let discoverable = agent.tools.discoverable_mcp_tool_names();

        assert!(names.contains(&"mcp"), "{names:?}");
        assert!(
            !discoverable.is_empty() && names.contains(&"mcp"),
            "discoverable tools {discoverable:?} must be reachable through `mcp`"
        );
        for tool in ["session_search", "session_read", "session_lineage_search"] {
            assert!(
                discoverable.iter().any(|name| name == tool),
                "{tool} should be discoverable through monty: {discoverable:?}"
            );
            assert!(
                !names.contains(&tool),
                "{tool} should not be directly injected: {names:?}"
            );
        }
    }

    #[test]
    fn assistant_explicit_grant_without_mcp_is_rejected_at_spawn() {
        use crate::agents::{AgentDef, AgentMode};
        let tmp = tempfile::tempdir().unwrap();
        let mut args = test_spawn_args(tmp.path());
        args.assistant_identity_prefix = Some("assistant identity".to_string());
        let mut def = AgentDef {
            name: "helper".to_string(),
            description: "assistant".to_string(),
            mode: AgentMode::Primary,
            model: None,
            temperature: None,
            tools: Some(vec!["session_search".to_string(), "read".to_string()]),
            tool_tiers: std::collections::BTreeMap::new(),
            tool_descriptions: std::collections::BTreeMap::new(),
            scan_tool_results: Some(true),
            goal_supervision: crate::agents::GoalSettingsOverride::default(),
            permission: None,
            capabilities: None,
            tool_steering: None,
            context_policy: None,
            vnext: None,
            prompt: "body".to_string(),
            prompt_overrides: std::collections::BTreeMap::new(),
            package_files: None,
            private_subagents: std::collections::BTreeMap::new(),
            source: tmp.path().join("helper.md"),
        };

        let err = match agent_from_def(&def, &args) {
            Ok(_) => panic!("assistant explicit grant without mcp unexpectedly succeeded"),
            Err(err) => err,
        };
        let msg = format!("{err}");
        assert!(msg.contains("session_search"), "{msg}");
        assert!(msg.contains("mcp"), "{msg}");

        def.tools = Some(vec!["read".to_string()]);
        let no_discoverable = agent_from_def(&def, &args).unwrap();
        assert!(
            no_discoverable
                .tools
                .discoverable_mcp_tool_names()
                .is_empty()
        );

        def.tools = Some(vec![
            "session_search".to_string(),
            "read".to_string(),
            "mcp".to_string(),
        ]);
        agent_from_def(&def, &args).unwrap();
    }

    #[test]
    fn legacy_tool_tier_frontmatter_is_refused_before_spawn() {
        let tmp = tempfile::tempdir().unwrap();
        let agents_dir = tmp.path().join(".cockpit").join("agents");
        std::fs::create_dir_all(&agents_dir).unwrap();
        std::fs::write(
            agents_dir.join("disabled-child.md"),
            "---\ndescription: child\nmode: subagent\ntools: [read, search]\ntoolTiers:\n  search: disabled\n---\nbody\n",
        )
        .unwrap();
        let args = test_spawn_args(tmp.path());

        let err = match crate::config::trust::with_workspace_trust_policy(
            trusted_policy(tmp.path()),
            || load("disabled-child", &args),
        ) {
            Ok(_) => panic!("schema-less tool authority must be rejected"),
            Err(err) => err,
        };
        let msg = format!("{err}");
        assert!(msg.contains("schemaVersion: 2"), "{msg}");

        std::fs::write(
            agents_dir.join("discoverable-child.md"),
            "---\ndescription: child\nmode: subagent\ntools: [read, search, mcp]\ntoolTiers:\n  search: discoverable\n---\nbody\n",
        )
        .unwrap();
        let err = match crate::config::trust::with_workspace_trust_policy(
            trusted_policy(tmp.path()),
            || load("discoverable-child", &args),
        ) {
            Ok(_) => panic!("schema-less discoverable tier must be rejected"),
            Err(err) => err,
        };
        assert!(format!("{err}").contains("schemaVersion: 2"));
    }

    #[test]
    fn tool_tier_assignments_are_fixed_in_constructed_agent() {
        use crate::agents::{AgentDef, AgentMode, ToolTier};
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        let mut tool_tiers = std::collections::BTreeMap::new();
        tool_tiers.insert("code".to_string(), ToolTier::Discoverable);
        let mut def = AgentDef {
            name: "custom-tiered".to_string(),
            description: "custom".to_string(),
            mode: AgentMode::Primary,
            model: None,
            temperature: None,
            tools: Some(vec![
                "read".to_string(),
                "code".to_string(),
                "mcp".to_string(),
            ]),
            tool_tiers,
            tool_descriptions: std::collections::BTreeMap::new(),
            scan_tool_results: Some(true),
            goal_supervision: crate::agents::GoalSettingsOverride::default(),
            permission: None,
            capabilities: None,
            tool_steering: None,
            context_policy: None,
            vnext: None,
            prompt: "body".to_string(),
            prompt_overrides: std::collections::BTreeMap::new(),
            package_files: None,
            private_subagents: std::collections::BTreeMap::new(),
            source: tmp.path().join("custom-tiered.md"),
        };
        let agent = agent_from_def(&def, &args).unwrap();
        def.tool_tiers.insert("code".to_string(), ToolTier::Enabled);

        assert!(!agent.tools.names().contains(&"code"));
        assert!(crate::mcp::builtin::describe(&host_for_agent(&agent, tmp.path()), "code").is_ok());
    }

    #[test]
    fn grep_glob_base_text_is_neutral_docs_answerer_restores_docs_phrasing() {
        let grep = crate::tools::grep::GrepTool;
        let glob = crate::tools::glob::GlobTool;
        for desc in [
            grep.description().to_string(),
            grep.verbose_description().unwrap(),
            glob.description().to_string(),
            glob.verbose_description().unwrap(),
        ] {
            assert!(!desc.contains("dependency you're inspecting"), "{desc}");
            assert!(!desc.contains("You have no shell here"), "{desc}");
        }

        let tmp = tempfile::tempdir().unwrap();
        let answerer = docs_answerer(&test_spawn_args(tmp.path())).unwrap();
        for tool in ["grep", "glob"] {
            let desc = answerer
                .tools
                .definitions(crate::agents::ToolSteering::Terse)
                .into_iter()
                .find(|definition| definition.name == tool)
                .unwrap()
                .description;
            assert!(desc.contains("dependency package"), "{desc}");
            assert!(desc.contains("no shell here"), "{desc}");
        }
    }

    #[test]
    fn tool_tier_prompt_files_do_not_name_moved_tools_as_direct() {
        let explore = include_str!("explore.md");
        for direct_list_line in explore
            .lines()
            .filter(|line| line.contains("tools") || line.starts_with("- `"))
        {
            for moved in ["`word`", "`hot`", "`circular`", "`impact`"] {
                assert!(
                    !direct_list_line.contains(moved),
                    "moved tool {moved} appears in direct-list line: {direct_list_line}"
                );
            }
        }

        for body in [include_str!("multireview.md")] {
            assert!(
                !body.contains("`harness_invoke`"),
                "multireview prompt must refer to the MCP harness advert"
            );
        }
    }

    #[test]
    fn monty_discoverability_invariant_covers_default_discoverable_tools() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        for &name in crate::agents::BUILTIN_AGENT_NAMES {
            let agent = load(name, &args).unwrap();
            let mcp_description = agent
                .tools
                .definitions(crate::agents::ToolSteering::Terse)
                .into_iter()
                .find(|definition| definition.name == "mcp")
                .map(|definition| definition.description)
                .unwrap_or_default();
            for tool in agent.tools.discoverable_mcp_tool_names() {
                assert!(
                    mcp_description.contains("grep_tool_names")
                        || mcp_description.contains("grep_tool_definitions")
                        || agent.role_prompt.contains(&tool),
                    "`{name}` discoverable tool `{tool}` is not reachable through static MCP discovery or role prompt"
                );
            }
        }
    }

    #[test]
    fn discoverable_tier_requires_mcp_on_every_builtin_agent() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());

        for &name in crate::agents::BUILTIN_AGENT_NAMES {
            let agent = load(name, &args).unwrap();
            let discoverable = agent.tools.discoverable_mcp_tool_names();
            if !discoverable.is_empty() {
                assert!(
                    agent.tools.names().contains(&"mcp"),
                    "`{name}` has discoverable tools {discoverable:?} but no direct `mcp` tool"
                );
            }
        }
    }

    #[test]
    fn defensive_role_uses_tiered_recall_tools_without_legacy_structural_authority() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        let agent = load("Careful", &args).unwrap();
        let names = agent.tools.names();
        let discoverable = agent.tools.discoverable_mcp_tool_names();

        assert_eq!(
            names,
            vec![
                "bash", "edit", "mcp", "question", "read", "search", "unlock", "write",
            ]
        );
        assert!(
            names.len() <= 10,
            "Careful direct tools should stay within the small-surface budget: {names:?}"
        );
        for non_direct in [
            "session_search",
            "session_read",
            "session_lineage_search",
            "todo",
            "webfetch",
            "websearch",
        ] {
            assert!(
                !names.contains(&non_direct),
                "{non_direct} must not be injected into Careful's direct tool surface"
            );
            assert!(
                discoverable.iter().any(|tool| tool == non_direct),
                "{non_direct} should stay reachable through mcp: {discoverable:?}"
            );
        }
    }

    #[test]
    fn defensive_wire_surface_is_smaller_than_normal() {
        let tmp = tempfile::tempdir().unwrap();
        let normal_args = test_spawn_args(tmp.path());
        let normal = load("Build", &normal_args).unwrap();

        let defensive_args = test_spawn_args(tmp.path());
        let defensive = load("Careful", &defensive_args).unwrap();

        let normal_names = normal.tools.names();
        let defensive_names = defensive.tools.names();
        assert!(
            defensive_names.len() <= 10,
            "Careful direct tools should stay within the small-surface budget: {defensive_names:?}"
        );
        assert!(
            defensive_names.len() < normal_names.len(),
            "Careful should expose fewer direct tools than normal Build: {defensive_names:?} vs {normal_names:?}"
        );
    }

    #[test]
    fn multireview_reaches_harness_tools_through_mcp() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        let agent = load("Multireview", &args).unwrap();
        let names = agent.tools.names();
        let discoverable = agent.tools.discoverable_mcp_tool_names();

        assert!(names.contains(&"mcp"), "{names:?}");
        assert!(
            discoverable.iter().any(|tool| tool == "harness_list"),
            "{discoverable:?}"
        );
        assert!(
            discoverable.iter().any(|tool| tool == "harness_invoke"),
            "{discoverable:?}"
        );

        let direct = multireview(&args);
        assert!(direct.tools.names().contains(&"mcp"));
    }

    #[test]
    fn read_workers_get_intel_tail_as_direct_builtins() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());

        // These read workers do not grant `mcp`, so the discoverable-tail
        // invariant would make `graph`/`change_impact` unreachable if they
        // were tiered behind monty here. Keep them direct until their grant
        // model changes.
        for name in ["explore", "scout", "bee"] {
            let agent = load(name, &args).unwrap();
            let names = agent.tools.names();
            let discoverable = agent.tools.discoverable_mcp_tool_names();

            assert!(discoverable.is_empty(), "`{name}`: {discoverable:?}");
            for tool in ["code", "graph", "change_impact"] {
                assert!(
                    names.contains(&tool),
                    "`{name}` missing `{tool}`: {names:?}"
                );
            }
            if matches!(name, "scout" | "bee") {
                assert!(names.contains(&"lsp"), "`{name}` missing `lsp`: {names:?}");
            }
        }
    }

    #[tokio::test]
    async fn unknown_agent_rejection_lists_bundled_reachable_set() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        let db = test_assistant_db();

        let message =
            unknown_agent_rejection_for_test(tmp.path(), &args.config, "Build", "missing", &db)
                .await
                .unwrap();

        assert!(message.contains("unknown agent `missing`"), "{message}");
        assert!(
            message.contains("Reachable agents from `Build`"),
            "{message}"
        );
        assert!(message.contains("builder"), "{message}");
        assert!(message.contains("explore"), "{message}");
        assert!(message.contains("docs"), "{message}");
    }

    #[tokio::test]
    async fn unknown_agent_rejection_includes_custom_subagents() {
        let tmp = tempfile::tempdir().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        std::fs::create_dir_all(&agents_dir).unwrap();
        std::fs::write(
            agents_dir.join("my-reviewer.md"),
            "---\ndescription: reviewer\nschemaVersion: 2\nagentId: authored/my-reviewer\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: Review source changes\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n---\nbody\n",
        )
        .unwrap();
        let args = test_spawn_args(tmp.path());
        let db = test_assistant_db();

        let message =
            unknown_agent_rejection_for_test(tmp.path(), &args.config, "Build", "missing", &db)
                .await
                .unwrap();

        assert!(message.contains("my-reviewer"), "{message}");
    }

    #[tokio::test]
    async fn unknown_agent_rejection_is_none_for_valid_agent() {
        let tmp = tempfile::tempdir().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        std::fs::create_dir_all(&agents_dir).unwrap();
        std::fs::write(
            agents_dir.join("custom-sub.md"),
            "---\ndescription: custom\nschemaVersion: 2\nagentId: authored/custom-sub\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: Perform coding work\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n---\nbody\n",
        )
        .unwrap();
        std::fs::write(
            agents_dir.join("custom-primary.md"),
            "---\ndescription: custom\nschemaVersion: 2\nagentId: authored/custom-primary\nexecutionKind: assistant\nmodelSlots:\n  primary:\n    purpose: Assist the user\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: true\n---\nbody\n",
        )
        .unwrap();
        let assistant_home = tmp.path().join("assistant-home");
        std::fs::create_dir_all(&assistant_home).unwrap();
        std::fs::write(
            assistant_home.join("assistant.md"),
            "---\nagentId: local/00000000-0000-0000-0000-000000000001\ndescription: assistant\nexecutionKind: assistant\nmodelSlots:\n  primary:\n    allowDefaultFallback: true\n    locality: any\n    minContextTokens: 1\n    purpose: Primary model\n    requiredCapabilities: [text_generation]\nschemaVersion: 2\n---\nassistant body\n",
        )
        .unwrap();
        let db = test_assistant_db();
        db.upsert_assistant(
            "helper-bot",
            assistant_home.to_str().unwrap(),
            "{}",
            crate::assistants::VALID_ASSISTANT_CONTENT_HASH_FIXTURE,
        )
        .await
        .unwrap();
        let args = test_spawn_args(tmp.path());

        for name in [
            "builder",
            "explore",
            "docs",
            "custom-sub",
            "custom-primary",
            "helper-bot",
        ] {
            assert!(
                unknown_agent_rejection_for_test(tmp.path(), &args.config, "Build", name, &db)
                    .await
                    .is_none(),
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn unknown_agent_rejection_refuses_parent_agent_name() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        let db = test_assistant_db();

        let message =
            unknown_agent_rejection_for_test(tmp.path(), &args.config, "Build", "Build", &db)
                .await
                .unwrap();

        assert!(message.contains("unknown agent `Build`"), "{message}");
        assert!(
            message.contains("Reachable agents from `Build`"),
            "{message}"
        );
        assert!(
            !message.contains("Reachable agents from `Build`: Build"),
            "{message}"
        );
    }

    #[tokio::test]
    async fn unknown_agent_rejection_refuses_docs_pipeline_stages() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        let db = test_assistant_db();

        for name in ["docs-resolver", "docs-answerer"] {
            let message =
                unknown_agent_rejection_for_test(tmp.path(), &args.config, "Build", name, &db)
                    .await
                    .expect("internal docs stages are not task targets");
            assert!(message.contains(name), "{message}");
            assert!(message.contains("builder"), "{message}");
        }
        assert!(
            unknown_agent_rejection_for_test(tmp.path(), &args.config, "Build", "docs", &db)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn unknown_agent_rejection_degrades_with_empty_reachable_set() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        let db = test_assistant_db();

        let message = unknown_agent_rejection_for_test(
            tmp.path(),
            &args.config,
            "locked-parent",
            "missing",
            &db,
        )
        .await
        .unwrap();

        assert!(message.contains("unknown agent `missing`"), "{message}");
        assert!(
            message.contains("no subagents are reachable from `locked-parent`"),
            "{message}"
        );
        assert!(!message.contains("Reachable agents from"), "{message}");
    }

    #[test]
    fn builtin_agent_grant_embedded_defs_validate_invariants() {
        for &name in crate::agents::BUILTIN_AGENT_NAMES {
            let def = crate::agents::embedded_default(name).expect("embedded builtin");
            crate::agents::validate_invariants(&def)
                .unwrap_or_else(|err| panic!("{name} embedded def violates invariants: {err}"));
        }
    }

    #[test]
    fn vnext_builtin_rejects_legacy_granted_tools_authority() {
        let tmp = tempfile::tempdir().unwrap();
        let mut args = test_spawn_args(tmp.path());
        args.interactive = false;
        args.granted_tools = vec!["harness_list".to_string()];

        let err = match load("explore", &args) {
            Ok(_) => panic!("vNext explore must reject legacy granted_tools authority"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("vNext definitions cannot receive legacy granted_tools authority"),
            "unexpected rejection: {err}"
        );
    }

    #[test]
    fn builtin_agent_grant_docs_answerer_only_tools_stay_ungrantable() {
        let tmp = tempfile::tempdir().unwrap();
        for tool in ["grep", "glob"] {
            let def = crate::agents::AgentDef {
                name: format!("user-{tool}"),
                description: "custom".to_string(),
                mode: crate::agents::AgentMode::Subagent,
                model: None,
                temperature: None,
                tools: Some(vec![tool.to_string()]),
                tool_tiers: std::collections::BTreeMap::new(),
                tool_descriptions: std::collections::BTreeMap::new(),
                scan_tool_results: None,
                goal_supervision: crate::agents::GoalSettingsOverride::default(),
                permission: None,
                capabilities: None,
                tool_steering: None,
                context_policy: None,
                vnext: None,
                prompt: "body".to_string(),
                prompt_overrides: std::collections::BTreeMap::new(),
                package_files: None,
                private_subagents: std::collections::BTreeMap::new(),
                source: tmp.path().join(format!("user-{tool}.md")),
            };
            let err = crate::agents::validate_invariants(&def)
                .expect_err("sandbox-only docs tools must be rejected for user defs");
            assert!(err.to_string().contains("docs-answerer-only"), "{err}");
            assert!(err.to_string().contains("sandboxed tool"), "{err}");
        }
    }

    fn write_project_config(cwd: &Path, body: &str) {
        let dir = cwd.join(".cockpit");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.json"), body).unwrap();
    }

    fn write_computer_provider_config(cwd: &Path, config_body: &str, provider_body: &str) {
        let dir = cwd.join(".cockpit");
        std::fs::create_dir_all(dir.join("providers")).unwrap();
        let config_path = dir.join("config.json");
        std::fs::write(&config_path, config_body).unwrap();
        let provider_path =
            crate::config::providers::provider_file_path_for_config(&config_path, "p").unwrap();
        std::fs::write(provider_path, provider_body).unwrap();
    }

    fn disk_model_spawn_args(cwd: &Path, model_id: &str) -> SpawnArgs {
        let _trust = crate::config::trust::enter_workspace_trust_policy(trusted_policy(cwd));
        let providers = crate::config::providers::ConfigDoc::load_effective(cwd);
        let model = Arc::new(
            crate::engine::model::Model::for_provider(
                &providers,
                "p",
                model_id,
                Arc::new(crate::redact::RedactionTable::empty()),
            )
            .unwrap(),
        );
        let mut args = test_spawn_args(cwd);
        args.model = model;
        args
    }

    fn task_target_names(agent: &Agent) -> Vec<String> {
        task_definition(agent, crate::agents::ToolSteering::Terse).parameters["properties"]
            ["payload"]["properties"]["agent"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect()
    }

    fn write_model_role_config(cwd: &Path) {
        let dir = cwd.join(".cockpit");
        std::fs::create_dir_all(dir.join("providers")).unwrap();
        std::fs::write(
            dir.join("config.json"),
            r#"{
              "smart_code": "lmstudio/smart",
              "cheap_code": "lmstudio/cheap",
              "agent_chooses_subagent_model": true,
              "active_model": { "provider": "lmstudio", "model": "local" }
            }"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("providers/lmstudio.json"),
            r#"{
              "url": "http://localhost:1/v1",
              "models": [
                { "id": "local", "subagent_invokable": true },
                { "id": "smart", "subagent_invokable": true },
                { "id": "cheap", "subagent_invokable": true }
              ]
            }"#,
        )
        .unwrap();
    }

    #[test]
    fn recursion_default_depth_is_seeded_and_clamped_by_max_depth() {
        use crate::config::extended::{DelegationConfig, DelegationRecursionPolicy};
        let mut cfg = DelegationConfig {
            default_recursion_depth: 1,
            ..DelegationConfig::default()
        };
        cfg.recursion.insert(
            "builder".to_string(),
            DelegationRecursionPolicy {
                allowed_targets: vec!["docs".to_string()],
                default_depth: Some(2),
                max_depth: Some(5),
            },
        );

        let ctx = configured_recursion_context(&cfg, "builder", None);
        assert_eq!(
            ctx.remaining_depth, 2,
            "maxDepth must not override defaultDepth"
        );
        assert_eq!(ctx.allowed_targets, vec!["docs".to_string()]);

        cfg.recursion.get_mut("builder").unwrap().default_depth = Some(8);
        let ctx = configured_recursion_context(&cfg, "builder", None);
        assert_eq!(
            ctx.remaining_depth, 5,
            "defaultDepth is clamped by maxDepth"
        );

        let ctx = configured_recursion_context(&cfg, "builder", Some(7));
        assert_eq!(
            ctx.remaining_depth, 5,
            "explicit remaining depth is also clamped"
        );
    }

    #[test]
    fn stock_builtin_load_honors_role_slots_and_task_model_selector() {
        let tmp = tempfile::tempdir().unwrap();
        write_model_role_config(tmp.path());

        let args = test_spawn_args(tmp.path());
        let builder = load("builder", &args).unwrap();
        assert_eq!(builder.model.model_id_ref(), "smart");

        let mut selected = test_spawn_args(tmp.path());
        selected.delegation_model =
            Some(crate::engine::model_roles::DelegationModelSelector::Exact {
                selector: "lmstudio:cheap".to_string(),
                required_capabilities: Vec::new(),
                min_context_tokens: None,
            });
        let explore = load("explore", &selected).unwrap();
        assert_eq!(explore.model.model_id_ref(), "cheap");
    }

    #[test]
    fn configured_custom_tools_cannot_collide_with_reserved_native_names() {
        for name in ["read", "write", "edit", "unlock", "task", "seed"] {
            let tmp = tempfile::tempdir().unwrap();
            write_project_config(
                tmp.path(),
                &format!(r#"{{"tools":{{"{name}":{{"enabled":true,"command":"echo hi"}}}}}}"#),
            );
            let err = match load("Build", &test_spawn_args(tmp.path())) {
                Ok(_) => panic!("reserved custom tool name must fail"),
                Err(err) => err.to_string(),
            };
            assert!(err.contains(name), "{err}");
            assert!(err.contains("reserved cockpit tool name"), "{err}");
        }
    }

    #[test]
    fn builtin_agent_prompts_contain_no_retired_lock_verbs() {
        // Deliberate retired-name coverage for the lock tool collapse.
        const RETIRED_LOCK_VERBS: &[&str] = &["readlock", "writeunlock", "editunlock"];
        let prompts = [
            ("builder", BUILDER_PROMPT),
            ("bee", BEE_PROMPT),
            ("build", BUILD_PROMPT),
        ];

        for (name, prompt) in prompts {
            for retired in RETIRED_LOCK_VERBS {
                assert!(
                    !prompt.contains(retired),
                    "{name} prompt still names retired lock verb `{retired}`"
                );
            }
        }
    }

    #[test]
    fn shared_tool_materialization_handles_grants_and_errors_loudly() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        let def = def_with_model(None);

        let tb = add_tool_by_name(crate::engine::tool::ToolBox::new(), "mcp", &def, &args).unwrap();
        assert!(tb.names().contains(&"mcp"));

        let granted = apply_grants(
            crate::engine::tool::ToolBox::new(),
            &["mcp".to_string()],
            &args,
        )
        .unwrap();
        assert!(granted.names().contains(&"mcp"));

        let err = match add_tool_by_name(crate::engine::tool::ToolBox::new(), "grep", &def, &args) {
            Ok(_) => panic!("grep materialization must fail"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("docs-answerer-only"), "{err}");

        let err = match apply_grants(
            crate::engine::tool::ToolBox::new(),
            &["not_a_tool".to_string()],
            &args,
        ) {
            Ok(_) => panic!("unknown grant must fail"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("unknown tool `not_a_tool`"), "{err}");
    }

    #[test]
    fn docs_answerer_is_noninteractive_read_only() {
        // Docs.2 (answerer) must NEVER be able to become interactive or have
        // a side effect: read-only exploration of cloned third-party source.
        // Its surface is exactly `read`/`grep`/`glob` — no `question` (the
        // only interactive tool), no `bash`/network/write, and no
        // `add-package` (the package-add gate lives on the resolver, not
        // here), so it cannot raise any prompt under any configuration.
        let tmp = tempfile::tempdir().unwrap();
        let agent = docs_answerer(&test_spawn_args(tmp.path())).unwrap();
        assert_eq!(agent.name, "docs-answerer");
        let mut names = agent.tools.names();
        names.sort_unstable();
        assert_eq!(
            names,
            vec!["glob", "grep", "read"],
            "docs answerer surface must be exactly read/grep/glob"
        );
        // Defensive belt-and-braces: explicitly assert the interactive /
        // side-effecting tools are absent.
        let names = agent.tools.names();
        for t in [
            "question",
            "bash",
            "webfetch",
            "websearch",
            "task",
            "add-package",
            "list-packages",
            "write",
            "edit",
        ] {
            assert!(!names.contains(&t), "docs answerer must not hold `{t}`");
        }
    }

    #[test]
    fn deepthink_is_hidden_by_default_and_advertised_when_enabled() {
        let tmp = tempfile::tempdir().unwrap();
        write_project_config(tmp.path(), r#"{"deepthink":{"enabled":false}}"#);
        let args = test_spawn_args(tmp.path());
        let task = task_definition(&build(&args), crate::agents::ToolSteering::Terse);
        let targets = task.parameters["properties"]["payload"]["properties"]["agent"]["enum"]
            .as_array()
            .unwrap()
            .clone();
        assert!(!targets.iter().any(|value| value == "deepthink"));

        write_project_config(tmp.path(), r#"{"deepthink":{"enabled":true}}"#);
        // Config is snapshotted onto `SpawnArgs` when built, so re-read it after
        // changing the config on disk (`engine-config-snapshot-adoption`).
        let args = test_spawn_args(tmp.path());
        let task = task_definition(&build(&args), crate::agents::ToolSteering::Terse);
        let targets = task.parameters["properties"]["payload"]["properties"]["agent"]["enum"]
            .as_array()
            .unwrap()
            .clone();
        assert!(targets.iter().any(|value| value == "deepthink"));
    }

    #[test]
    fn computer_subagent_requires_vision() {
        let tmp = tempfile::tempdir().unwrap();
        write_computer_provider_config(
            tmp.path(),
            "{}",
            r#"{
                "url": "http://localhost:1/v1",
                "computer_use": "yolo",
                "models": [
                    {
                        "id": "text",
                        "subagent_invokable": true,
                        "capabilities": {
                            "image_input": "unsupported",
                            "computer_use": { "contract": "open_ai_responses" }
                        }
                    }
                ]
            }"#,
        );
        let text_args = disk_model_spawn_args(tmp.path(), "text");
        let err = match load("computer", &text_args) {
            Ok(_) => panic!("non-vision-only computer provider should not load"),
            Err(err) => err.to_string(),
        };
        assert!(
            err.contains("requires a configured vision-capable"),
            "{err}"
        );

        write_computer_provider_config(
            tmp.path(),
            "{}",
            r#"{
                "url": "http://localhost:1/v1",
                "computer_use": "yolo",
                "models": [
                    {
                        "id": "text",
                        "subagent_invokable": true,
                        "capabilities": { "image_input": "unsupported" }
                    },
                    {
                        "id": "vision",
                        "subagent_invokable": true,
                        "capabilities": {
                            "image_input": "supported",
                            "computer_use": { "contract": "open_ai_responses" }
                        }
                    }
                ]
            }"#,
        );
        // Re-snapshot the config after adding the vision-capable model on disk
        // (`engine-config-snapshot-adoption`).
        let text_args = disk_model_spawn_args(tmp.path(), "text");
        let agent = load("computer", &text_args).unwrap();
        assert_eq!(agent.model.provider_id(), "p");
        assert_eq!(agent.model.model_id_ref(), "vision");
        assert!(agent.params.native_computer.is_some());
    }

    #[test]
    fn nonvision_delegates_not_direct() {
        let tmp = tempfile::tempdir().unwrap();
        write_computer_provider_config(
            tmp.path(),
            "{}",
            r#"{
                "url": "http://localhost:1/v1",
                "computer_use": "yolo",
                "models": [
                    {
                        "id": "text",
                        "subagent_invokable": true,
                        "capabilities": { "image_input": "unsupported" }
                    },
                    {
                        "id": "vision",
                        "subagent_invokable": true,
                        "capabilities": {
                            "image_input": "supported",
                            "computer_use": { "contract": "open_ai_responses" }
                        }
                    }
                ]
            }"#,
        );

        let text_agent = build(&disk_model_spawn_args(tmp.path(), "text"));
        assert!(text_agent.params.native_computer.is_none());
        let text_targets = task_target_names(&text_agent);
        assert!(text_targets.iter().any(|target| target == "computer"));

        let vision_agent = build(&disk_model_spawn_args(tmp.path(), "vision"));
        assert!(vision_agent.params.native_computer.is_some());
    }

    #[test]
    fn disabled_hides_computer() {
        let tmp = tempfile::tempdir().unwrap();
        write_computer_provider_config(
            tmp.path(),
            "{}",
            r#"{
                "url": "http://localhost:1/v1",
                "computer_use": "disabled",
                "models": [
                    {
                        "id": "text",
                        "subagent_invokable": true,
                        "capabilities": { "image_input": "unsupported" }
                    },
                    {
                        "id": "vision",
                        "subagent_invokable": true,
                        "capabilities": {
                            "image_input": "supported",
                            "computer_use": { "contract": "open_ai_responses" }
                        }
                    }
                ]
            }"#,
        );

        let args = disk_model_spawn_args(tmp.path(), "vision");
        let agent = build(&args);
        assert!(agent.params.native_computer.is_none());
        let targets = task_target_names(&agent);
        assert!(!targets.iter().any(|target| target == "computer"));
        let err = match load("computer", &args) {
            Ok(_) => panic!("disabled computer-use provider should not load"),
            Err(err) => err.to_string(),
        };
        assert!(
            err.contains("requires a configured vision-capable"),
            "{err}"
        );
    }

    #[test]
    fn ask_routes_to_approval() {
        let tmp = tempfile::tempdir().unwrap();
        let _trust = crate::config::trust::enter_workspace_trust_policy(trusted_policy(tmp.path()));
        write_computer_provider_config(
            tmp.path(),
            "{}",
            r#"{
                "url": "http://localhost:1/v1",
                "computer_use": "ask",
                "models": [
                    {
                        "id": "vision",
                        "subagent_invokable": true,
                        "capabilities": {
                            "image_input": "supported",
                            "computer_use": { "contract": "open_ai_responses" }
                        }
                    }
                ]
            }"#,
        );
        let args = disk_model_spawn_args(tmp.path(), "vision");
        let providers = crate::config::providers::ConfigDoc::load_effective(tmp.path());
        let resolved = resolved_computer_use_for_model(&providers, tmp.path(), &args.model);

        assert_eq!(resolved.tier, crate::config::extended::ComputerUseMode::Ask);
        assert!(resolved.requires_approval);
        assert!(
            resolved
                .native_computer
                .as_ref()
                .is_some_and(|computer| computer.approval_required)
        );

        let agent = load("computer", &args).unwrap();
        assert!(
            agent
                .params
                .native_computer
                .as_ref()
                .is_some_and(|computer| computer.approval_required)
        );
    }

    #[test]
    fn deepthink_factory_is_tool_free_even_with_grants() {
        let tmp = tempfile::tempdir().unwrap();
        let mut args = test_spawn_args(tmp.path());
        args.delegated = true;
        args.delegation_recursion = DelegationRecursionContext {
            enabled: true,
            remaining_depth: 2,
            allowed_targets: vec!["deepthink".to_string()],
            same_model_only: false,
        };
        args.granted_tools = vec!["read".to_string(), "bash".to_string(), "mcp".to_string()];

        let agent = load("deepthink", &args).unwrap();
        assert_eq!(agent.name, "deepthink");
        assert!(agent.tools.names().is_empty(), "{:?}", agent.tools.names());
        assert_eq!(agent.delegation_recursion.remaining_depth, 0);
        for heading in [
            "summary:",
            "recommendation:",
            "risks:",
            "assumptions:",
            "open_questions:",
        ] {
            assert!(
                agent.role_prompt.contains(heading),
                "deepthink prompt missing {heading}"
            );
        }
    }

    #[test]
    fn explore_is_read_only_noninteractive_others_are_not() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        // `explore`: noninteractive + holds no write/lock tools → in scope.
        assert!(is_read_only_noninteractive(&explore(&args)));
        // `builder`: holds the lock/write tools → out of scope (writer).
        assert!(!is_read_only_noninteractive(&builder(&args)));
        // `Build`: a primary that delegates + holds `task` — not a read-only
        // noninteractive subagent either (it's interactive/primary, and the
        // `docs` pipeline is excluded structurally by name in the helper).
        assert!(!is_read_only_noninteractive(&build(&args)));
    }

    /// `is_write_capable` is structural (derived from the held lock/write
    /// tools), not name-bound: `builder` holds them, `explore` does not. A
    /// write-capable follow-up uses this to decide whether to re-acquire locks
    /// hash-matched (implementation note).
    #[test]
    fn write_capability_is_tool_derived() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        assert!(is_write_capable(&builder(&args)));
        assert!(!is_write_capable(&explore(&args)));
    }

    #[test]
    fn vnext_explore_cannot_receive_legacy_mcp_grant() {
        let tmp = tempfile::tempdir().unwrap();
        let base = test_spawn_args(tmp.path());

        // No MCP in `explore`'s base surface.
        let plain = load("explore", &base).unwrap();
        assert!(!plain.tools.names().contains(&"mcp"));

        // A vNext delegation must use the typed effective-grant path instead
        // of the legacy per-tool authority list.
        let granted_args = SpawnArgs {
            granted_tools: vec!["mcp".to_string()],
            ..test_spawn_args(tmp.path())
        };
        let err = match load("explore", &granted_args) {
            Ok(_) => panic!("vNext explore must reject legacy granted_tools authority"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("vNext definitions cannot receive legacy granted_tools authority"),
            "unexpected rejection: {err}"
        );

        // The rejected legacy grant does not mutate another spawn.
        let after = load("explore", &test_spawn_args(tmp.path())).unwrap();
        assert!(!after.tools.names().contains(&"mcp"));
    }

    #[test]
    fn builtin_prompts_have_no_mode_suffixed_files() {
        // Issue #75 ratchet: the retired `.normal.md`/`.frontier.md` prompt
        // bodies are gone; each bundled agent has a single canonical body.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/engine/builtin");
        let entries = std::fs::read_dir(&dir).unwrap();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".normal.md") || name.ends_with(".frontier.md") {
                panic!(
                    "builtin prompt dir still contains mode-suffixed file `{name}` — issue #75 requires a single canonical body"
                );
            }
        }
    }

    #[test]
    fn learn_is_reachable_from_write_capable_build() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        let agent = build(&args);
        assert!(agent.tools.names().contains(&"skill_manage"));
    }

    #[test]
    fn delegate_agent_defs_expose_tiered_docs_policy() {
        for (name, body) in [
            ("build", BUILD_PROMPT),
            ("builder", BUILDER_PROMPT),
            ("bee", BEE_PROMPT),
        ] {
            let low = body.to_lowercase();
            assert!(
                low.contains("docs"),
                "`{name}` must name the `docs` route for dependency usage"
            );
            assert!(
                low.contains("first move"),
                "`{name}` defensive body must make `docs` the first move"
            );
            assert!(
                low.contains("guess"),
                "`{name}` must steer away from guessing the API"
            );
            assert!(
                low.contains("web-search") || low.contains("web search"),
                "`{name}` must steer away from web-searching the API"
            );
        }
        for (name, body) in [
            ("build", BUILD_PROMPT),
            ("builder", BUILDER_PROMPT),
            ("bee", BEE_PROMPT),
        ] {
            let low = body.to_lowercase();
            assert!(low.contains("docs"), "`{name}` must name docs");
            assert!(
                low.contains("by default"),
                "`{name}` normal body must make docs the default for uncertainty"
            );
            assert!(
                low.contains("unfamiliar") || low.contains("version-sensitive"),
                "`{name}` normal body must scope docs to API uncertainty"
            );
            assert!(
                low.contains("guess") || low.contains("web-search") || low.contains("web search"),
                "`{name}` body must steer away from guessing/web-searching uncertain APIs"
            );
        }
    }

    #[test]
    fn with_custom_tools_keeps_native_web_tools_and_user_tool_for_firecrawl() {
        let tmp = tempfile::tempdir().unwrap();
        let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        write_project_config(
            tmp.path(),
            r#"{
                "web": { "provider": "firecrawl" },
                "tools": {
                    "my_tool": {
                        "enabled": true,
                        "command": "echo {value}"
                    }
                }
            }"#,
        );

        let tb = with_custom_tools(
            ToolBox::new(),
            &crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path()),
            tmp.path(),
            &std::collections::BTreeSet::new(),
        );
        let names = tb.names();
        assert!(names.contains(&"webfetch"), "{names:?}");
        assert!(names.contains(&"websearch"), "{names:?}");
        assert!(names.contains(&"my_tool"), "{names:?}");
    }

    #[test]
    fn with_custom_tools_registers_typed_custom_web_tools() {
        let tmp = tempfile::tempdir().unwrap();
        let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        write_project_config(
            tmp.path(),
            r#"{
                "web": {
                    "provider": "custom",
                    "custom": {
                        "fetch_command": "fetch-cli {url}",
                        "search_command": "search-cli {query}"
                    }
                }
            }"#,
        );

        let tb = with_custom_tools(
            ToolBox::new(),
            &crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path()),
            tmp.path(),
            &std::collections::BTreeSet::new(),
        );
        let names = tb.names();
        assert!(names.contains(&"webfetch"), "{names:?}");
        assert!(names.contains(&"websearch"), "{names:?}");
        let webfetch = tb.get("webfetch").unwrap();
        assert_eq!(
            webfetch.description(),
            crate::tools::custom::neutral_web_description("webfetch").unwrap()
        );
    }

    #[test]
    fn with_custom_tools_registers_only_nonblank_custom_web_commands() {
        let tmp = tempfile::tempdir().unwrap();
        let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        write_project_config(
            tmp.path(),
            r#"{
                "web": {
                    "provider": "custom",
                    "custom": {
                        "fetch_command": "fetch-cli {url}",
                        "search_command": "   "
                    }
                }
            }"#,
        );

        let tb = with_custom_tools(
            ToolBox::new(),
            &crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path()),
            tmp.path(),
            &std::collections::BTreeSet::new(),
        );
        let names = tb.names();
        assert!(names.contains(&"webfetch"), "{names:?}");
        assert!(!names.contains(&"websearch"), "{names:?}");
    }

    #[test]
    fn with_custom_tools_allows_blank_custom_web_provider() {
        let tmp = tempfile::tempdir().unwrap();
        let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        write_project_config(tmp.path(), r#"{"web":{"provider":"custom"}}"#);

        let tb = with_custom_tools(
            ToolBox::new(),
            &crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path()),
            tmp.path(),
            &std::collections::BTreeSet::new(),
        );
        let names = tb.names();
        assert!(!names.contains(&"webfetch"), "{names:?}");
        assert!(!names.contains(&"websearch"), "{names:?}");
    }

    #[test]
    fn reserved_custom_tool_name_includes_typed_web_tools() {
        assert!(is_reserved_custom_tool_name("webfetch"));
        assert!(is_reserved_custom_tool_name("websearch"));
    }

    #[test]
    fn builtin_inventory_tracks_grantable_tool_names() {
        let inventory = builtin_tool_inventory()
            .iter()
            .map(|tool| tool.name)
            .collect::<std::collections::HashSet<_>>();
        let intentionally_web_section = ["webfetch", "websearch"];
        for name in known_agent_tool_names() {
            assert!(
                inventory.contains(name) || intentionally_web_section.contains(name),
                "`{name}` is grantable but absent from the builtin inventory"
            );
        }
        for name in inventory {
            assert!(
                known_agent_tool_names().contains(&name)
                    || extra_custom_tool_reserved_names().contains(&name),
                "`{name}` is inventoried but not backed by a runtime/reserved tool name"
            );
        }
    }

    #[test]
    fn intel_inventory_summaries_are_accurate() {
        let intel: std::collections::BTreeMap<_, _> = builtin_tool_inventory()
            .iter()
            .filter(|tool| tool.family == "Intel")
            .map(|tool| (tool.name, tool.summary.to_ascii_lowercase()))
            .collect();
        assert_eq!(
            intel.keys().copied().collect::<Vec<_>>(),
            ["change_impact", "code", "context_pack", "graph", "search"]
        );

        let search = intel.get("search").expect("search summary");
        assert!(search.contains("search"), "{search}");
        assert!(search.contains("regular expression"), "{search}");

        let code = intel.get("code").expect("code summary");
        assert!(code.contains("structure"), "{code}");
        assert!(code.contains("symbols"), "{code}");

        let context_pack = intel.get("context_pack").expect("context_pack summary");
        assert!(context_pack.contains("context"), "{context_pack}");
        assert!(context_pack.contains("bundle"), "{context_pack}");

        let graph = intel.get("graph").expect("graph summary");
        assert!(
            graph.contains("mtime") || graph.contains("recent"),
            "{graph}"
        );
        assert!(!graph.contains("centrality"), "{graph}");

        let change_impact = intel.get("change_impact").expect("change_impact summary");
        assert!(change_impact.contains("impact"), "{change_impact}");
        assert!(change_impact.contains("local changes"), "{change_impact}");
    }

    #[test]
    fn known_agent_tool_names_matches_materialize_tool_by_name() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        let names = known_agent_tool_names();
        assert!(names.contains(&"todo"));
        assert!(names.contains(&"session_lineage_search"));
        // `goal` is deliberately not a grantable/runtime tool: the session goal
        // is host/driver-owned durable state, not a tool an agent may mention in
        // `tools:` (see `worker_cannot_create_or_mutate_goal`). Its retired
        // sub-action verbs must also stay ungrantable.
        assert!(!names.contains(&"goal"));
        for removed in [
            format!("todo_{}", "read"),
            format!("create_{}", "goal"),
            format!("get_{}", "goal"),
            format!("update_{}", "goal"),
        ] {
            assert!(
                !names.contains(&removed.as_str()),
                "{removed} should not be grantable"
            );
        }
        for name in ["todo", "session_lineage_search"] {
            let tb = materialize_tool_by_name(ToolBox::new(), name, None, &args).unwrap();
            assert_eq!(tb.names(), vec![name]);
        }
    }

    /// Dead native `handoff` tool must not be grantable, inventoried, or
    /// materializable. Written first so it fails while the tool remains
    /// registered, then passes after deletion.
    #[test]
    fn builtin_inventory_excludes_dead_handoff() {
        let names = known_agent_tool_names();
        assert!(
            !names.contains(&"handoff"),
            "known_agent_tool_names must not list handoff: {names:?}"
        );
        assert!(
            !builtin_tool_inventory()
                .iter()
                .any(|tool| tool.name == "handoff"),
            "builtin_tool_inventory must not list handoff"
        );
        assert!(
            !invariant_builtin_tools()
                .into_iter()
                .any(|tool| tool.name() == "handoff"),
            "invariant_builtin_tools must not materialize HandoffTool"
        );
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        match materialize_tool_by_name(ToolBox::new(), "handoff", None, &args) {
            Ok(_) => panic!("handoff must not materialize"),
            Err(err) => {
                let err = err.to_string();
                assert!(
                    err.contains("unknown tool"),
                    "materialize_tool_by_name(handoff) must fail as unknown tool: {err}"
                );
            }
        }
    }

    /// Module + source file for the dead native handoff tool must be gone.
    #[test]
    fn handoff_tool_source_and_module_are_removed() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tools/handoff.rs");
        assert!(
            !path.exists(),
            "tools/handoff.rs must be deleted (still present at {})",
            path.display()
        );
        let tools_mod = include_str!("../../tools/mod.rs");
        assert!(
            !tools_mod.contains("mod handoff"),
            "tools/mod.rs must not export the handoff module"
        );
    }

    /// Live same-word "handoff" features remain after the dead native tool is
    /// removed: CompactReady, /compact assembly, todo note kind, plan notes
    /// path, expand_handoff_tags, and BTW inventory without a handoff tool.
    #[test]
    fn live_handoff_named_features_unchanged() {
        use crate::engine::agent::TurnEvent;
        use crate::engine::compact::{StateAppendix, assemble_handoff};

        // CompactReady still carries a handoff string field (compaction).
        let compact_ready = TurnEvent::CompactReady {
            new_session_id: uuid::Uuid::nil(),
            handoff: "brief".into(),
            brief: "brief body".into(),
            source: "test".into(),
            trigger_ctx_pct: None,
            tokens_before: 0,
            tokens_after: 0,
            turns_summarized: 0,
            tail_kept: 0,
            tail_trimmed: 0,
            seed_tool_count: 0,
            seed_tool_tokens: 0,
        };
        match &compact_ready {
            TurnEvent::CompactReady { handoff, brief, .. } => {
                assert_eq!(handoff, "brief");
                assert_eq!(brief, "brief body");
            }
            other => panic!("expected CompactReady, got {other:?}"),
        }
        // Drop forces the variant shape to be constructed (not merely named).
        drop(compact_ready);

        // /compact still assembles review-ready handoff text.
        let appendix = StateAppendix {
            files_read: Vec::new(),
            files_edited: Vec::new(),
            commands: Vec::new(),
            git_branch: None,
            dirty_files: None,
            open_todos: Vec::new(),
            active_goal: None,
            task_overview: Vec::new(),
            pinned_messages: Vec::new(),
        };
        let assembled = assemble_handoff("brief body", &appendix, &[], false);
        assert!(
            assembled.contains("brief body"),
            "assemble_handoff must keep brief: {assembled}"
        );

        // Todo note kind `handoff` remains a first-class enum value.
        assert_eq!(
            crate::db::task_todos::TodoNoteKind::Handoff.as_str(),
            "handoff"
        );
        let todo_kind = serde_json::to_value(crate::db::task_todos::TodoNoteKind::Handoff).unwrap();
        assert_eq!(todo_kind, serde_json::json!("handoff"));

        // expand_handoff_tags remains on the driver (delegation tag expansion).
        let driver_src = include_str!("../driver/mod.rs");
        assert!(
            driver_src.contains("fn expand_handoff_tags("),
            "expand_handoff_tags must remain as a callable"
        );

        // Plan handoff notes helpers remain for plan→build handoff notes.
        let plan_src = include_str!("../../tools/plan_doc.rs");
        assert!(
            plan_src.contains("fn plan_handoff_notes")
                && plan_src.contains("fn find_existing_build_handoff"),
            "plan-doc handoff note helpers must remain"
        );

        // BTW tool-effect closed set (Monty inventory) has no handoff tool entry.
        let effects: std::collections::BTreeMap<_, _> = invariant_builtin_tools()
            .into_iter()
            .map(|tool| (tool.name().to_string(), tool.effect()))
            .collect();
        assert!(!effects.contains_key("handoff"), "{effects:?}");
        assert!(effects.contains_key("task"), "{effects:?}");
        assert!(effects.contains_key("todo"), "{effects:?}");
    }

    #[test]
    fn skill_inventory_summary_is_accurate() {
        let skill = builtin_tool_inventory()
            .iter()
            .find(|tool| tool.name == "skill")
            .expect("skill inventory item");

        assert_eq!(
            skill.summary,
            "Load named skill instructions and package support files."
        );
        assert!(!skill.summary.contains("Run user-invocable skills"));
    }

    /// The per-agent `task` description override (`Build`/`builder`) follows
    /// terse vs verbose steering.
    #[test]
    fn task_override_uses_tiered_docs_policy_by_steering() {
        let tmp = tempfile::tempdir().unwrap();
        let build_args = test_spawn_args_with_vnext_grant(tmp.path(), "Build");
        let builder_args = test_spawn_args_with_vnext_grant(tmp.path(), "builder");
        for (steering, expect_first_move) in [
            (crate::agents::ToolSteering::Terse, false),
            (crate::agents::ToolSteering::Verbose, true),
        ] {
            for build_agent in [load("Build", &build_args).unwrap(), builder(&builder_args)] {
                let defs = build_agent.tools.definitions(steering);
                let task = defs
                    .iter()
                    .find(|d| d.name == "task")
                    .unwrap_or_else(|| panic!("`{}` must hold `task`", build_agent.name));
                let low = task.description.to_lowercase();
                assert!(
                    low.contains("docs"),
                    "`{}` ({steering:?}) `task` desc must name `docs`: {}",
                    build_agent.name,
                    task.description
                );
                if expect_first_move {
                    assert!(
                        low.contains("first move"),
                        "`{}` verbose `task` desc must make docs the first move: {}",
                        build_agent.name,
                        task.description
                    );
                } else {
                    assert!(
                        low.contains("by default") && low.contains("unfamiliar"),
                        "`{}` terse `task` desc must make docs the default for uncertainty: {}",
                        build_agent.name,
                        task.description
                    );
                }
            }
        }
    }

    /// Delegation context clarity (implementation note
    /// Part B): each delegated agent's definition frames its identity as "how I
    /// work" while deferring "what to do right now" to the brief + any seeded
    /// skill, which take precedence where they conflict — WITHOUT relaxing tool
    /// discipline. Asserts the wording fix for the `0ccstv` shape (a `builder`
    /// told "draft, don't implement" must follow the brief, not implement).
    #[test]
    fn explore_prompts_advertise_native_intel_tools() {
        for (name, prompt) in [("explore", EXPLORE_PROMPT), ("explore", EXPLORE_PROMPT)] {
            for tool in ["context_pack", "code", "search", "graph", "bash"] {
                assert!(
                    prompt.contains(tool),
                    "`{name}` prompt must mention `{tool}`"
                );
            }
            assert!(
                prompt.to_lowercase().contains("native"),
                "`{name}` prompt should prefer native intel tools"
            );
        }
    }

    #[test]
    fn explore_never_gets_removed_seed_tool() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        assert!(!explore(&args).tools.names().contains(&"seed"));
    }

    #[test]
    fn delegated_children_omit_task_without_recursive_budget() {
        let tmp = tempfile::tempdir().unwrap();
        let mut args = test_spawn_args(tmp.path());
        args.delegated = true;
        args.delegation_recursion = DelegationRecursionContext::default();

        assert!(!builder(&args).tools.names().contains(&"task"));
        assert!(!explore(&args).tools.names().contains(&"task"));
        assert!(!bee(&args).tools.names().contains(&"task"));
    }

    #[test]
    fn vnext_definition_does_not_expose_legacy_task_without_effective_grant() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        let mut def = crate::agents::embedded_default("explore").unwrap();
        // v2 rejects this spelling at the markdown boundary, but retain the
        // runtime assertion as defense in depth for trusted/internal callers
        // that construct an AgentDef directly.
        def.tools = Some(vec!["task".to_string()]);

        let agent = agent_from_def(&def, &args).unwrap();
        assert!(!agent.tools.names().contains(&"task"));
    }

    #[test]
    fn vnext_recursive_local_child_uses_authenticated_snapshot_over_workspace_shadow() {
        use crate::agents::{AllowedChild, DelegationPolicy, DelegationTarget};

        let tmp = tempfile::tempdir().unwrap();
        let shadow_dir = tmp.path().join(".cockpit/agents");
        std::fs::create_dir_all(&shadow_dir).unwrap();
        std::fs::write(
            shadow_dir.join("nested-child.md"),
            "---\ndescription: workspace shadow\nschemaVersion: 2\nagentId: authored/nested-child\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: Investigate code\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n---\nworkspace shadow",
        )
        .unwrap();

        let installation_id =
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000004").unwrap();
        let mut local_child = crate::agents::embedded_default("explore").unwrap();
        local_child.name = "nested-child".to_string();
        local_child.prompt = "authenticated local snapshot".to_string();
        // The authenticated snapshot replaces the full authored body; do not
        // retain embedded posture-keyed prompt variants that would mask it.
        local_child.prompt_overrides.clear();
        local_child.vnext.as_mut().unwrap().agent_id =
            "local/00000000-0000-0000-0000-000000000004".to_string();

        let resolver = crate::agents::LocalInstallationResolver::from_bound_definitions(
            std::collections::BTreeMap::from([(installation_id, local_child)]),
        )
        .unwrap();
        let mut parent = crate::agents::embedded_default("Build").unwrap();
        let parent_vnext = parent.vnext.as_mut().unwrap();
        parent_vnext.agent_id = "local/00000000-0000-0000-0000-000000000005".to_string();
        parent_vnext.delegation = DelegationPolicy {
            allowed_children: vec![AllowedChild::LocalInstallation { installation_id }],
            max_descendant_depth: Some(1),
            max_concurrent_children: Some(1),
            targets: vec![DelegationTarget::SameRoot],
            default_child: None,
        };
        let mut args = test_spawn_args(tmp.path());
        args.delegated = true;
        args.parent_vnext_grant = Some(
            parent_vnext
                .resolve_grant(&crate::agents::VnextHostPolicy::for_session_config(
                    &args.config.extended(),
                ))
                .unwrap(),
        );
        args.vnext_host_policy = Some(Arc::new(
            crate::agents::VnextHostPolicy::for_session_config(&args.config.extended()),
        ));
        args.vnext_local_installation_resolver = resolver;

        let child = load("nested-child", &args).unwrap();
        assert_eq!(child.role_prompt, "authenticated local snapshot");
        assert_eq!(
            child
                .vnext_grant
                .as_ref()
                .map(|grant| grant.agent_id.as_str()),
            Some("local/00000000-0000-0000-0000-000000000004")
        );
    }

    #[test]
    fn delegated_builder_advertises_only_vnext_granted_targets() {
        let tmp = tempfile::tempdir().unwrap();
        let mut args = test_spawn_args_with_vnext_grant(tmp.path(), "builder");
        args.delegated = true;

        let agent = builder(&args);
        let task = task_definition(&agent, crate::agents::ToolSteering::Terse);
        let agent_enum = task.parameters["properties"]["payload"]["properties"]["agent"]["enum"]
            .as_array()
            .expect("agent enum");
        assert_eq!(agent_enum, &vec![serde_json::json!("explore")]);
    }

    #[test]
    fn delegated_vnext_builder_cannot_expand_targets_with_legacy_recursion() {
        let tmp = tempfile::tempdir().unwrap();
        write_project_config(tmp.path(), r#"{"deepthink":{"enabled":true}}"#);
        let mut args = test_spawn_args_with_vnext_grant(tmp.path(), "builder");
        args.delegated = true;
        args.delegation_recursion = DelegationRecursionContext {
            enabled: true,
            remaining_depth: 1,
            allowed_targets: vec!["deepthink".to_string()],
            same_model_only: false,
        };

        let agent = builder(&args);
        let task = task_definition(&agent, crate::agents::ToolSteering::Terse);
        let agent_enum = task.parameters["properties"]["payload"]["properties"]["agent"]["enum"]
            .as_array()
            .expect("agent enum");
        assert_eq!(agent_enum, &vec![serde_json::json!("explore")]);
    }

    #[test]
    fn delegated_explore_stays_leaf_without_task_grant() {
        let tmp = tempfile::tempdir().unwrap();
        let mut args = test_spawn_args(tmp.path());
        args.delegated = true;
        args.delegation_recursion = DelegationRecursionContext {
            enabled: true,
            remaining_depth: 1,
            allowed_targets: vec!["explore".to_string()],
            same_model_only: true,
        };

        let agent = explore(&args);
        assert!(!agent.tools.names().contains(&"task"));
        assert!(is_read_only_noninteractive(&agent));
    }

    #[test]
    fn build_task_description_is_per_agent_overridden_and_composes_with_steering() {
        // `Build` registers a per-agent override on `task` (delegate-eager
        // intent, prompt `per-agent-tool-definitions.md`). The override wins
        // over the tool's own description under both terse and verbose
        // steering, and leaves the SCHEMA untouched — same tool ID +
        // parameters as the base `task` tool.
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        let build_agent = build(&args);

        let task_terse = build_agent
            .tools
            .definitions(crate::agents::ToolSteering::Terse)
            .into_iter()
            .find(|d| d.name == "task")
            .expect("Build holds task");
        let task_verbose = build_agent
            .tools
            .definitions(crate::agents::ToolSteering::Verbose)
            .into_iter()
            .find(|d| d.name == "task")
            .expect("Build holds task");

        // The override text is present (delegate-eager intent), not the tool's
        // own base description.
        assert!(
            task_terse.description.contains("substantive feature work"),
            "Build terse `task` must carry the per-agent intent: {}",
            task_terse.description
        );
        // Terse and verbose select different text — steering axis preserved
        // on top of the per-agent override.
        assert_ne!(task_terse.description, task_verbose.description);

        // SCHEMA is identical to the un-overridden `task` tool: same ID + same
        // parameters. The override never touched the schema.
        let base = crate::tools::task::TaskTool::with_subagents(
            &build_subagents(
                &crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(
                    tmp.path(),
                ),
                tmp.path(),
            )
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        );
        let base_def =
            crate::engine::tool::definition_of(&base, crate::agents::ToolSteering::Terse, None);
        assert_eq!(task_terse.name, base_def.name);
        assert_eq!(task_terse.parameters, base_def.parameters);
        // …and the description genuinely differs from the un-overridden one.
        assert_ne!(task_terse.description, base_def.description);
    }

    fn task_definition(
        agent: &Agent,
        steering: crate::agents::ToolSteering,
    ) -> crate::engine::message::ToolDefinition {
        agent
            .tools
            .definitions(steering)
            .into_iter()
            .find(|d| d.name == "task")
            .expect("agent holds task")
    }

    #[test]
    fn verbose_build_task_description_preserve_delegation_steer() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());

        let agent = build(&args);
        let task = task_definition(&agent, crate::agents::ToolSteering::Verbose);

        for needle in [
            "Delegate substantive implementation instead of doing it inline",
            "Each `builder` task is one implementation slice",
            "follow-up implementation iteration after `builder` returns",
            "start a fresh `builder` brief seeded with the prior result summary",
            "your first move is `docs`",
            "preparing a `builder` brief",
            "inline work is limited to orchestration and short read-only lookups",
            "backgrounded task_delegation JSON envelope",
            "do not treat it as the report or redelegate solely because it backgrounded",
            "Read each child status/error",
        ] {
            assert!(
                task.description.contains(needle),
                "Build verbose task description missing `{needle}`:\n{}",
                task.description
            );
        }
    }

    #[test]
    fn verbose_builder_task_description_preserve_scope_steer() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args_with_vnext_grant(tmp.path(), "builder");

        let agent = builder(&args);
        let task = task_definition(&agent, crate::agents::ToolSteering::Verbose);

        for needle in [
            "Use `task` only to ask the `docs` pipeline",
            "asking `docs` is your first move",
            "exact usage pattern is clearly established in already-read local code",
            "Do exactly one assigned implementation slice",
            "Do not try to delegate the feature itself",
            "return the out-of-scope ask to your caller via the structured `return` report",
            "docs task returns backgrounded",
            "read child status/error",
        ] {
            assert!(
                task.description.contains(needle),
                "builder verbose task description missing `{needle}`:\n{}",
                task.description
            );
        }

        let enum_values: Vec<&str> =
            task.parameters["properties"]["payload"]["properties"]["agent"]["enum"]
                .as_array()
                .expect("agent enum")
                .iter()
                .map(|value| value.as_str().expect("string enum value"))
                .collect();
        assert_eq!(enum_values, vec!["explore"]);
    }

    #[test]
    fn terse_build_and_builder_task_descriptions_stay_terse() {
        let tmp = tempfile::tempdir().unwrap();
        let build_args = test_spawn_args_with_vnext_grant(tmp.path(), "Build");
        let builder_args = test_spawn_args_with_vnext_grant(tmp.path(), "builder");

        let build_task = task_definition(
            &load("Build", &build_args).unwrap(),
            crate::agents::ToolSteering::Terse,
        );
        let builder_task = task_definition(
            &load("builder", &builder_args).unwrap(),
            crate::agents::ToolSteering::Terse,
        );

        assert!(build_task.description.contains("substantive feature work"));
        assert!(build_task.description.contains("backgrounded JSON"));
        assert!(build_task.description.contains("detached/result-pending"));
        assert!(build_task.description.contains("use docs by default"));
        assert!(
            build_task
                .description
                .contains("version-sensitive dependency APIs")
        );
        assert!(
            builder_task
                .description
                .contains("Use `task` only for docs")
        );
        assert!(builder_task.description.contains("docs backgrounds"));
        assert!(builder_task.description.contains("detached/result-pending"));
        assert!(
            !build_task
                .description
                .contains("follow-up implementation iteration"),
            "{}",
            build_task.description
        );
        assert!(
            !builder_task
                .description
                .contains("structured `return` report"),
            "{}",
            builder_task.description
        );
        assert!(
            build_task.description.len() < 520,
            "terse Build task description grew too verbose: {}",
            build_task.description
        );
        assert!(
            builder_task.description.len() < 320,
            "terse builder task description grew too verbose: {}",
            builder_task.description
        );
    }

    #[test]
    fn markdown_agent_tool_description_override_applies_keeping_schema_uniform() {
        // A markdown agent authors a `tool_descriptions:` override; it lands on
        // the constructed toolbox via `with_override`, re-wording only the
        // description while the schema stays identical to the same tool on
        // another agent (here `explore`, which holds `read` with no override).
        use crate::agents::{AgentDef, AgentMode, ToolDescriptionSpec};
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());

        let mut tool_descriptions = std::collections::BTreeMap::new();
        tool_descriptions.insert(
            "read".to_string(),
            ToolDescriptionSpec::Text("builder: read the file you will edit yourself".to_string()),
        );
        let def = AgentDef {
            name: "builder".to_string(),
            description: "do-it-yourself".to_string(),
            mode: AgentMode::Primary,
            model: None,
            temperature: None,
            tools: Some(vec![
                "read".to_string(),
                "bash".to_string(),
                "mcp".to_string(),
            ]),
            tool_tiers: std::collections::BTreeMap::new(),
            tool_descriptions,
            scan_tool_results: Some(true),
            goal_supervision: crate::agents::GoalSettingsOverride::default(),
            permission: None,
            capabilities: None,
            tool_steering: None,
            context_policy: None,
            vnext: None,
            prompt: "body".to_string(),
            prompt_overrides: std::collections::BTreeMap::new(),
            package_files: None,
            private_subagents: std::collections::BTreeMap::new(),
            source: std::path::PathBuf::from("builder.md"),
        };
        let agent = agent_from_def(&def, &args).unwrap();
        let read_def = agent
            .tools
            .definitions(crate::agents::ToolSteering::Terse)
            .into_iter()
            .find(|d| d.name == "read")
            .expect("builder holds read");
        assert_eq!(
            read_def.description,
            "builder: read the file you will edit yourself"
        );

        // Same tool on `explore` (no override): SAME ID + SAME SCHEMA, but the
        // base description — proving per-agent description variation with a
        // uniform schema.
        let explore_read = explore(&args)
            .tools
            .definitions(crate::agents::ToolSteering::Terse)
            .into_iter()
            .find(|d| d.name == "read")
            .expect("explore holds read");
        assert_eq!(read_def.name, explore_read.name);
        assert_eq!(read_def.parameters, explore_read.parameters);
        assert_ne!(read_def.description, explore_read.description);
    }

    #[test]
    fn custom_agent_without_tools_gets_defaults_and_config_driven_web() {
        use crate::agents::{AgentDef, AgentMode};
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        let def = AgentDef {
            name: "custom-reader".to_string(),
            description: "custom".to_string(),
            mode: AgentMode::Primary,
            model: None,
            temperature: None,
            tools: None,
            tool_tiers: std::collections::BTreeMap::new(),
            tool_descriptions: std::collections::BTreeMap::new(),
            scan_tool_results: Some(true),
            goal_supervision: crate::agents::GoalSettingsOverride::default(),
            permission: None,
            capabilities: None,
            tool_steering: None,
            context_policy: None,
            vnext: None,
            prompt: "body".to_string(),
            prompt_overrides: std::collections::BTreeMap::new(),
            package_files: None,
            private_subagents: std::collections::BTreeMap::new(),
            source: tmp.path().join("custom-reader.md"),
        };

        let agent = agent_from_def(&def, &args).unwrap();
        let names = agent.tools.names();
        assert!(names.contains(&"read"));
        assert!(names.contains(&"search"));
        assert!(names.contains(&"websearch"));
        assert!(names.contains(&"webfetch"));
    }

    #[tokio::test]
    async fn can_delegate_false_hides_delegation_tools() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args_with_provider_can_delegate(tmp.path(), Some(false));
        let agent = build(&args);
        let session = crate::session::Session::create_for_test(
            crate::db::Db::open_in_memory().unwrap(),
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();

        let toolbox = crate::engine::agent::turn_toolbox(
            &agent,
            &session,
            tmp.path(),
            &crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path()),
        )
        .await;
        let names = toolbox.names();

        assert!(!names.contains(&"task"), "{names:?}");
        assert!(!names.contains(&"spawn"), "{names:?}");
    }

    #[tokio::test]
    async fn can_delegate_unset_keeps_delegation_tools() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args_with_provider_can_delegate(tmp.path(), None);
        let agent = build(&args);
        let session = crate::session::Session::create_for_test(
            crate::db::Db::open_in_memory().unwrap(),
            tmp.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();

        let toolbox = crate::engine::agent::turn_toolbox(
            &agent,
            &session,
            tmp.path(),
            &crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path()),
        )
        .await;
        let names = toolbox.names();

        assert!(names.contains(&"task"), "{names:?}");
        assert!(!names.contains(&"spawn"), "{names:?}");
    }

    #[tokio::test]
    async fn can_delegate_gates_subagent_turns() {
        // Subagent and primary turns share `turn_toolbox`; proving the filter
        // there covers every spawned child before the model sees its tools.
        let tmp = tempfile::tempdir().unwrap();
        let mut args = test_spawn_args_with_provider_can_delegate(tmp.path(), Some(false));
        args.delegated = true;
        let agent = bee(&args);
        let session = crate::session::Session::create_for_test(
            crate::db::Db::open_in_memory().unwrap(),
            tmp.path().to_path_buf(),
            "bee",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();

        let toolbox = crate::engine::agent::turn_toolbox(
            &agent,
            &session,
            tmp.path(),
            &crate::daemon::session_worker::SessionConfigHandle::from_disk_for_tests(tmp.path()),
        )
        .await;
        let names = toolbox.names();

        assert!(!names.contains(&"task"), "{names:?}");
        assert!(!names.contains(&"spawn"), "{names:?}");
    }

    #[test]
    fn bee_factory_is_write_capable_worker_with_spawn_no_base_mcp() {
        // `bee` (GOALS §24/§26): the recursive parallel worker. Write-capable
        // (lock/write tools), full intel, `task→docs` only, recursive `spawn`,
        // structured `return`, NO base MCP (parent-grantable). Noninteractive.
        let tmp = tempfile::tempdir().unwrap();
        let agent = bee(&test_spawn_args(tmp.path()));
        assert_eq!(agent.name, "bee");
        let names = agent.tools.names();
        for t in [
            "read", "bash", "write", "edit", "unlock", "code", "search", "skill", "task", "spawn",
            "return",
        ] {
            assert!(names.contains(&t), "bee missing `{t}`: {names:?}");
        }
        // No base MCP — granted per task by the parent.
        assert!(!names.contains(&"mcp"), "bee must not hold base `mcp`");
        // `bee` is write-capable and noninteractive by default.
        assert!(is_write_capable(&agent));
        assert!(is_noninteractive("bee"));
        // Its only `task` target is the `docs` pipeline (no general delegation).
        let def = agent
            .tools
            .definitions(crate::agents::ToolSteering::Verbose)
            .into_iter()
            .find(|d| d.name == "task")
            .expect("bee holds task");
        let enum_vals = def.parameters["properties"]["payload"]["properties"]["agent"]["enum"]
            .as_array()
            .expect("agent enum present");
        let targets: Vec<&str> = enum_vals.iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(targets, vec!["docs"], "bee task targets: {targets:?}");
    }

    #[test]
    fn build_task_targets_exclude_primaries() {
        // The `task` enum must offer only normal subagents
        // (builder/explore/docs) — never primaries.
        let tmp = tempfile::tempdir().unwrap();
        let agent = build(&test_spawn_args(tmp.path()));
        let def = agent
            .tools
            .definitions(crate::agents::ToolSteering::Verbose)
            .into_iter()
            .find(|d| d.name == "task")
            .expect("task tool present");
        let enum_vals = def.parameters["properties"]["payload"]["properties"]["agent"]["enum"]
            .as_array()
            .expect("agent enum present");
        let names: Vec<&str> = enum_vals.iter().filter_map(|v| v.as_str()).collect();
        assert!(names.contains(&"builder"), "{names:?}");
        assert!(names.contains(&"explore"), "{names:?}");
        for forbidden in ["Plan", "Build", "Careful", "Swarm", "Auto"] {
            assert!(
                !names.contains(&forbidden),
                "`task` must not target the primary `{forbidden}`: {names:?}"
            );
        }
    }

    #[test]
    fn spawn_description_carries_depth_and_dedicated_folder_guidance() {
        // The per-task effective depth + ceiling are baked into the tool
        // description so the model can self-limit, and the description tells
        // the caller to give each child a dedicated write scope/DB (the
        // primary contention-avoidance mechanism, GOALS §24 / §10).
        let tmp = tempfile::tempdir().unwrap();
        let mut args = test_spawn_args(tmp.path());
        args.swarm_depth = 1;
        args.swarm_max_depth = 4;
        let agent = bee(&args);
        let def = agent
            .tools
            .definitions(crate::agents::ToolSteering::Terse)
            .into_iter()
            .find(|d| d.name == "spawn")
            .expect("spawn tool present");
        let desc = &def.description;
        assert!(desc.contains("depth 1"), "depth in description: {desc}");
        assert!(desc.contains("ceiling 4"), "ceiling in description: {desc}");
        assert!(
            desc.contains("write_scope") && desc.contains("dedicated"),
            "dedicated-folder/DB guidance in description: {desc}"
        );
    }

    /// A bare [`crate::agents::AgentDef`] carrying an optional frontmatter
    /// `model`, for exercising [`resolve_agent_model`] precedence.
    fn def_with_model(model: Option<&str>) -> crate::agents::AgentDef {
        crate::agents::AgentDef {
            name: "custom".to_string(),
            description: "x".to_string(),
            mode: crate::agents::AgentMode::default(),
            model: model.map(str::to_string),
            temperature: None,
            tools: None,
            tool_tiers: std::collections::BTreeMap::new(),
            tool_descriptions: std::collections::BTreeMap::new(),
            scan_tool_results: None,
            goal_supervision: crate::agents::GoalSettingsOverride::default(),
            permission: None,
            capabilities: None,
            tool_steering: None,
            context_policy: None,
            vnext: None,
            prompt: "body".to_string(),
            prompt_overrides: std::collections::BTreeMap::new(),
            package_files: None,
            private_subagents: std::collections::BTreeMap::new(),
            source: std::path::PathBuf::new(),
        }
    }

    /// A second, distinct [`Model`] to stand in for a plan-level override, so
    /// the precedence assertions can compare by pointer identity.
    fn override_model() -> Arc<Model> {
        use crate::config::providers::{ActiveModelRef, ProviderEntry, ProvidersConfig};
        use std::collections::BTreeMap;
        let mut providers = BTreeMap::new();
        providers.insert(
            "lmstudio".to_string(),
            ProviderEntry {
                url: "http://localhost:1/v1".into(),
                headers: vec![],
                ..ProviderEntry::default()
            },
        );
        let pcfg = ProvidersConfig {
            providers,
            active_model: Some(ActiveModelRef {
                provider: "lmstudio".into(),
                model: "override".into(),
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            }),
            ..ProvidersConfig::default()
        };
        Arc::new(
            Model::from_config(
                &pcfg,
                std::sync::Arc::new(crate::redact::RedactionTable::empty()),
            )
            .unwrap(),
        )
    }

    #[test]
    fn plan_model_override_beats_frontmatter() {
        let tmp = tempfile::tempdir().unwrap();
        let mut args = test_spawn_args(tmp.path());
        let over = override_model();
        args.model_override = Some(over.clone());
        // Even with a frontmatter model set, the plan-level override wins.
        let def = def_with_model(Some("anthropic/claude-opus-4-8"));
        let resolved = resolve_agent_model(&def, &args).unwrap();
        assert!(Arc::ptr_eq(&resolved, &over));
    }

    #[test]
    fn delegated_vnext_model_override_cannot_bypass_unprepared_slot_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let mut args = test_spawn_args(tmp.path());
        args.delegated = true;
        let over = override_model();
        args.model_override = Some(over);
        let def = crate::agents::embedded_default("explore").expect("embedded vNext agent");

        let resolved = resolve_agent_model(&def, &args).unwrap();
        assert!(
            Arc::ptr_eq(&resolved, &args.model),
            "a raw delegated override is not authority to pick an unprepared vNext child model"
        );
    }

    #[test]
    fn unprepared_delegated_vnext_child_uses_session_model() {
        let tmp = tempfile::tempdir().unwrap();
        let mut args = test_spawn_args(tmp.path());
        args.delegated = true;
        for name in ["builder", "explore"] {
            let def = crate::agents::embedded_default(name).expect("embedded vNext agent");
            assert!(
                def.vnext
                    .as_ref()
                    .and_then(|vnext| vnext.model_slots.get("primary"))
                    .is_some_and(|slot| slot.models.is_empty()),
                "`{name}` builtin primary.models must stay empty (any compatible offering)"
            );
            let resolved = resolve_agent_model(&def, &args).unwrap();
            assert!(
                Arc::ptr_eq(&resolved, &args.model),
                "unprepared delegated `{name}` must keep the session model"
            );
        }
    }

    fn slot_model(provider: &str, model: &str, default: bool) -> crate::agents::SlotModelRef {
        crate::agents::SlotModelRef {
            provider_id: provider.to_string(),
            model_id: model.to_string(),
            default,
        }
    }

    fn vnext_def_with_primary_models(
        models: Vec<crate::agents::SlotModelRef>,
    ) -> crate::agents::AgentDef {
        let mut def = crate::agents::embedded_default("explore").expect("embedded vNext agent");
        def.vnext
            .as_mut()
            .expect("explore is vNext")
            .model_slots
            .get_mut("primary")
            .expect("primary slot")
            .models = models;
        def
    }

    fn unprepared_spawn_args_with_slot_providers(
        cwd: &Path,
        agent_chooses_subagent_model: bool,
    ) -> SpawnArgs {
        use crate::config::providers::{ActiveModelRef, ProviderEntry, ProvidersConfig};
        use std::collections::BTreeMap;
        let mut args = test_spawn_args(cwd);
        let mut providers = BTreeMap::new();
        providers.insert(
            "lmstudio".to_string(),
            ProviderEntry {
                url: "http://localhost:1/v1".into(),
                headers: vec![],
                ..ProviderEntry::default()
            },
        );
        let pcfg = ProvidersConfig {
            providers,
            active_model: Some(ActiveModelRef {
                provider: "lmstudio".into(),
                model: "local".into(),
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            }),
            ..ProvidersConfig::default()
        };
        let extended = ExtendedConfig {
            agent_chooses_subagent_model,
            ..ExtendedConfig::default()
        };
        args.model = Arc::new(
            Model::from_config(
                &pcfg,
                std::sync::Arc::new(crate::redact::RedactionTable::empty()),
            )
            .unwrap(),
        );
        args.config = crate::daemon::session_worker::SessionConfigHandle::detached(
            crate::daemon::session_worker::SessionConfigSnapshot::new(0, pcfg, extended),
        );
        args.delegated = true;
        args
    }

    #[test]
    fn unprepared_delegated_vnext_child_with_authored_models_uses_slot_default() {
        let tmp = tempfile::tempdir().unwrap();
        let args = unprepared_spawn_args_with_slot_providers(tmp.path(), false);
        let def = vnext_def_with_primary_models(vec![
            slot_model("lmstudio", "slot-default", true),
            slot_model("lmstudio", "slot-alt", false),
        ]);
        assert_eq!(args.model.provider_id(), "lmstudio");
        assert_eq!(args.model.model_id_ref(), "local");

        let resolved = resolve_agent_model(&def, &args).unwrap();
        assert_eq!(resolved.provider_id(), "lmstudio");
        assert_eq!(
            resolved.model_id_ref(),
            "slot-default",
            "unprepared child with a non-empty models list must run the authored default, not inherit a session model outside the allowed set"
        );
    }

    #[test]
    fn unprepared_delegated_vnext_child_does_not_inherit_allowed_non_default_session_model() {
        let tmp = tempfile::tempdir().unwrap();
        let args = unprepared_spawn_args_with_slot_providers(tmp.path(), false);
        let def = vnext_def_with_primary_models(vec![
            slot_model("lmstudio", "slot-default", true),
            slot_model("lmstudio", "local", false),
        ]);

        let resolved = resolve_agent_model(&def, &args).unwrap();
        assert_eq!(resolved.provider_id(), "lmstudio");
        assert_eq!(
            resolved.model_id_ref(),
            "slot-default",
            "an allowed session model is still not a parent-named selector; the child runs its slot default"
        );
    }

    #[test]
    fn unprepared_delegated_vnext_child_honors_parent_named_allowed_non_default() {
        let tmp = tempfile::tempdir().unwrap();
        let mut args = unprepared_spawn_args_with_slot_providers(tmp.path(), true);
        args.delegation_model = Some(crate::engine::model_roles::DelegationModelSelector::Exact {
            selector: "lmstudio/slot-alt".into(),
            required_capabilities: Vec::new(),
            min_context_tokens: None,
        });
        let def = vnext_def_with_primary_models(vec![
            slot_model("lmstudio", "slot-default", true),
            slot_model("lmstudio", "slot-alt", false),
        ]);

        let resolved = resolve_agent_model(&def, &args).unwrap();
        assert_eq!(resolved.provider_id(), "lmstudio");
        assert_eq!(
            resolved.model_id_ref(),
            "slot-alt",
            "a parent-named selector in the authored list must beat the slot default"
        );
    }

    #[test]
    fn unprepared_delegated_vnext_child_refuses_parent_named_model_outside_authored_set() {
        let tmp = tempfile::tempdir().unwrap();
        let mut args = unprepared_spawn_args_with_slot_providers(tmp.path(), true);
        args.delegation_model = Some(crate::engine::model_roles::DelegationModelSelector::Exact {
            selector: "lmstudio/local".into(),
            required_capabilities: Vec::new(),
            min_context_tokens: None,
        });
        let def = vnext_def_with_primary_models(vec![
            slot_model("lmstudio", "slot-default", true),
            slot_model("lmstudio", "slot-alt", false),
        ]);

        let Err(err) = resolve_agent_model(&def, &args) else {
            panic!("parent-named model outside the authored list must be a structured refusal");
        };
        let message = format!("{err:#}");
        assert!(
            message.contains("lmstudio/local")
                && message.contains("not in the child slot allowed route set"),
            "parent-named model outside the authored list must be a structured refusal, got: {message}"
        );
    }

    #[test]
    fn unprepared_vnext_root_with_authored_models_keeps_session_model() {
        let tmp = tempfile::tempdir().unwrap();
        let mut args = unprepared_spawn_args_with_slot_providers(tmp.path(), false);
        args.delegated = false;
        let def = vnext_def_with_primary_models(vec![
            slot_model("lmstudio", "slot-default", true),
            slot_model("lmstudio", "slot-alt", false),
        ]);
        assert_eq!(args.model.provider_id(), "lmstudio");
        assert_eq!(args.model.model_id_ref(), "local");
        assert!(args.model_override.is_none());

        let resolved = resolve_agent_model(&def, &args).unwrap();
        assert!(
            Arc::ptr_eq(&resolved, &args.model),
            "unprepared root with a non-empty models list must keep the session/persisted model, not snap to the authored default"
        );
    }

    #[test]
    fn unprepared_vnext_root_with_authored_models_honors_picker_override() {
        let tmp = tempfile::tempdir().unwrap();
        let mut args = unprepared_spawn_args_with_slot_providers(tmp.path(), false);
        args.delegated = false;
        let over = override_model();
        args.model_override = Some(over.clone());
        let def = vnext_def_with_primary_models(vec![
            slot_model("lmstudio", "slot-default", true),
            slot_model("lmstudio", "slot-alt", false),
        ]);

        let resolved = resolve_agent_model(&def, &args).unwrap();
        assert!(
            Arc::ptr_eq(&resolved, &over),
            "unprepared root picker override must beat both the session model and the authored slot default"
        );
    }

    #[test]
    fn no_override_no_frontmatter_uses_session_model() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        // No plan override, no frontmatter selector → the session model.
        let def = def_with_model(None);
        let resolved = resolve_agent_model(&def, &args).unwrap();
        assert!(Arc::ptr_eq(&resolved, &args.model));
    }

    #[test]
    fn compose_system_prompt_for_model_prepends_model_instructions() {
        let tmp = tempfile::tempdir().unwrap();
        let mut args = test_spawn_args(tmp.path());
        let mut snapshot = ModelSystemPromptSnapshot::empty();
        snapshot.insert("lmstudio", "local", "MODEL INSTRUCTIONS".to_string());
        args.model_system_prompt_snapshot = Arc::new(snapshot);

        let out = compose_system_prompt_for_model("ROLE PROMPT", &args.model, &args);
        assert!(
            out.starts_with("MODEL INSTRUCTIONS\n\nROLE PROMPT"),
            "block was: {out}"
        );
        let model_at = out.find("MODEL INSTRUCTIONS").unwrap();
        let role_at = out.find("ROLE PROMPT").unwrap();
        let harness_at = out.find("Harness: cockpit").unwrap();
        assert!(
            model_at < role_at && role_at < harness_at,
            "block was: {out}"
        );
    }

    #[test]
    fn identity_prompt_slot_order() {
        let tmp = tempfile::tempdir().unwrap();
        let mut args = test_spawn_args(tmp.path());
        args.assistant_identity_prefix = Some(
            "Assistant identity (SOUL.md):\nSOUL BODY\n\nHuman context (USER.md):\nUSER BODY\n\n"
                .to_string(),
        );

        let out = compose_system_prompt_for_model("DEFINITION BODY", &args.model, &args);
        let soul_at = out.find("SOUL BODY").unwrap();
        let user_at = out.find("USER BODY").unwrap();
        let def_at = out.find("DEFINITION BODY").unwrap();
        let harness_at = out.find("Harness: cockpit").unwrap();

        assert!(
            soul_at < user_at && user_at < def_at && def_at < harness_at,
            "block was: {out}"
        );
    }

    #[test]
    fn compose_system_prompt_for_model_is_byte_identical_without_match() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        let existing = compose_system_prompt("ROLE PROMPT", &args.session_short_id, &args.cwd);
        let with_snapshot = compose_system_prompt_for_model("ROLE PROMPT", &args.model, &args);
        assert_eq!(with_snapshot, existing);
    }

    /// Config with a name set, used by the deterministic name-present case.
    fn cfg_with_name(name: &str) -> ExtendedConfig {
        ExtendedConfig {
            name: Some(name.to_string()),
            ..ExtendedConfig::default()
        }
    }

    #[test]
    fn compose_system_prompt_appends_identity_os_and_session() {
        let tmp = tempfile::tempdir().unwrap();
        let out = compose_system_prompt("ROLE PROMPT", "abc123", tmp.path());
        assert!(out.starts_with("ROLE PROMPT"));
        // Harness identity carries the actual build version.
        assert!(out.contains(&format!("Harness: cockpit {}", env!("CARGO_PKG_VERSION"))));
        // Both URLs are present (explicit user decision — keep both).
        assert!(out.contains("https://flycockpit.dev"));
        assert!(out.contains("https://app.flycockpit.dev"));
        assert!(out.contains("Operating system:"));
        assert!(out.contains("Session: abc123"));
        // The absolute working directory is anchored in the block (GOALS
        // §17g, §12): the model sees its real cwd, not a fabricated prefix.
        assert!(
            out.contains(&format!("Working directory: {}", tmp.path().display())),
            "block was: {out}"
        );
    }

    /// A parameterized-cwd subagent (e.g. the `docs` answerer launched in a
    /// package directory) must show *that* cwd, not the project root. The
    /// builder receives the spawn cwd, so passing a distinct directory here
    /// emits that directory's path.
    #[test]
    fn compose_system_prompt_anchors_parameterized_subagent_cwd() {
        let project = tempfile::tempdir().unwrap();
        let pkg_dir = project.path().join("clones/somepkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        let out = compose_system_prompt("ROLE PROMPT", "abc123", &pkg_dir);
        assert!(
            out.contains(&format!("Working directory: {}", pkg_dir.display())),
            "block was: {out}"
        );
        // Not the parent/project root.
        assert!(
            !out.contains(&format!(
                "Working directory: {}\n",
                project.path().display()
            )),
            "block was: {out}"
        );
    }

    #[test]
    fn compose_system_prompt_omits_session_when_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let out = compose_system_prompt("ROLE PROMPT", "", tmp.path());
        assert!(out.contains("Operating system:"));
        assert!(!out.contains("Session:"));
    }

    /// Name-present case. Driven through the pure assembler with an
    /// explicit config so the assertion is independent of whichever
    /// layered config the host machine happens to resolve.
    #[test]
    fn compose_system_prompt_includes_user_name_when_configured() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_with_name("Ada");
        let out = compose_system_prompt_with("ROLE PROMPT", "abc123", tmp.path(), &cfg);
        assert!(out.contains("User: Ada"), "block was: {out}");
        // Order: the User line sits between the URL line and the OS line.
        let user_at = out.find("User: Ada").unwrap();
        let url_at = out.find("Website: https://flycockpit.dev").unwrap();
        let os_at = out.find("Operating system:").unwrap();
        assert!(url_at < user_at && user_at < os_at, "block was: {out}");
    }

    /// Whitespace-only names are treated as absent (trimmed before the
    /// emptiness check).
    #[test]
    fn compose_system_prompt_omits_user_name_when_blank() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = cfg_with_name("   ");
        let out = compose_system_prompt_with("ROLE PROMPT", "abc123", tmp.path(), &cfg);
        assert!(!out.contains("User:"), "block was: {out}");
    }

    /// Name-absent case. Default config has `name: None`, so the User
    /// line must be omitted entirely.
    #[test]
    fn compose_system_prompt_omits_user_name_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = ExtendedConfig::default();
        let out = compose_system_prompt_with("ROLE PROMPT", "abc123", tmp.path(), &cfg);
        assert!(!out.contains("User:"), "block was: {out}");
    }

    #[test]
    fn system_prompt_has_no_skill_catalog() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = ExtendedConfig::default();
        let out = compose_system_prompt_with("ROLE PROMPT", "abc123", tmp.path(), &cfg);

        assert!(!out.contains(crate::skills::MODEL_SKILL_CATALOG_LABEL));
        assert!(!out.contains("- deploy:"));
    }

    /// Wiring test: the layered loader actually reads `name` out of a
    /// `config.json`. Written into the `.cockpit/` dir of the
    /// test cwd — the project-scoped layer the discovery walk-up finds
    /// ([`load_extended_config`] → [`discover_config_dirs`]).
    #[test]
    fn load_extended_config_reads_name_from_project_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".cockpit");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.json"), r#"{"name":"Christopher"}"#).unwrap();
        // A real home-layer config may take precedence in discovery order
        // on a developer machine; assert the project-dir value is at least
        // reachable by loading that file directly through the same loader.
        let cfg = crate::config::extended::ExtendedConfigDoc::load(&dir.join("config.json"))
            .unwrap()
            .config();
        assert_eq!(cfg.name.as_deref(), Some("Christopher"));
        let out = compose_system_prompt_with("ROLE PROMPT", "abc123", tmp.path(), &cfg);
        assert!(out.contains("User: Christopher"), "block was: {out}");
    }

    #[test]
    fn compose_system_prompt_normalizes_trailing_newline() {
        let tmp = tempfile::tempdir().unwrap();
        let with_nl = compose_system_prompt("ROLE\n", "abc123", tmp.path());
        let without_nl = compose_system_prompt("ROLE", "abc123", tmp.path());
        // The role-prompt's own newline is preserved either way; the
        // appended lines are identical in both cases.
        assert!(with_nl.contains("\nOperating system:"));
        assert!(without_nl.contains("\nOperating system:"));
    }

    #[test]
    fn compose_system_prompt_excludes_project_guidance_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("AGENTS.md"), "RULES").unwrap();
        let out = compose_system_prompt("ROLE", "abc", tmp.path());
        assert!(!out.contains("Project guidance"));
        assert!(!out.contains("RULES"));
    }

    /// Contract test: when multiple configured filenames exist in the
    /// same directory, only the first entry in the user's config list
    /// is loaded. The other files must not contribute.
    #[test]
    fn find_agent_guidance_only_loads_first_match_when_multiple_exist() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("AGENTS.md"), "A-CONTENT").unwrap();
        std::fs::write(tmp.path().join("project guidance"), "C-CONTENT").unwrap();

        let names = vec!["AGENTS.md".to_string(), "project guidance".to_string()];
        let (path, body) = find_agent_guidance(tmp.path(), &names).expect("expected a hit");
        assert!(path.ends_with("AGENTS.md"), "got {path:?}");
        assert_eq!(body, "A-CONTENT");

        // Reverse the order: project guidance now wins, AGENTS.md is ignored.
        let names_rev = vec!["project guidance".to_string(), "AGENTS.md".to_string()];
        let (path2, body2) = find_agent_guidance(tmp.path(), &names_rev).expect("expected a hit");
        assert!(path2.ends_with("project guidance"), "got {path2:?}");
        assert_eq!(body2, "C-CONTENT");
    }

    /// Same shape, but the second-listed file lives in a parent dir.
    /// The first-listed file in the same starting cwd still wins.
    #[test]
    fn find_agent_guidance_first_match_wins_across_ancestors() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("AGENTS.md"), "FROM-SUB").unwrap();
        std::fs::write(tmp.path().join("project guidance"), "FROM-ROOT").unwrap();

        // From `sub`, AGENTS.md is right there — project guidance in the
        // parent must not be loaded.
        let names = vec!["AGENTS.md".to_string(), "project guidance".to_string()];
        let (path, body) = find_agent_guidance(&sub, &names).expect("expected a hit");
        assert!(path.ends_with("sub/AGENTS.md"), "got {path:?}");
        assert_eq!(body, "FROM-SUB");
    }
}
