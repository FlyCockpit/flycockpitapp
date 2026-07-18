//! Built-in agent definitions: `Build`, `builder`.
//!
//! The agent prompts live as Markdown documents alongside this file.
//! `include_str!` bakes them into the binary so a fresh `cargo install
//! cockpit-cli` ships with the bundled cast (GOALS §3a). User-authored
//! agents go through [`crate::agents`] / `agent_dirs`; they're the
//! extension path.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Result, bail};

use crate::config::extended::ToolCommandTemplate;
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
// The flat `<name>.md` body is the `defensive` variant **and** the
// mode-agnostic flat fallback (implementation note):
// defensive is the default and the more explicit, scaffolded body
// (weak-model-first, priority #1). `<name>.normal.md` is the terser
// strong-model body. Optional frontier bodies are the most autonomous
// variant.
// [`builtin_prompt_for`] selects between them; an agent lacking the frontier
// file falls back to normal, and one lacking normal falls back to the flat
// body, so the flat-fallback contract holds belt-and-suspenders.
pub(crate) const AUTO_PROMPT: &str = include_str!("auto.md");
pub(crate) const AUTO_PROMPT_NORMAL: &str = include_str!("auto.normal.md");
pub(crate) const BUILD_PROMPT: &str = include_str!("build.md");
pub(crate) const BUILD_PROMPT_NORMAL: &str = include_str!("build.normal.md");
pub(crate) const BUILD_PROMPT_FRONTIER: &str = include_str!("build.frontier.md");
pub(crate) const BUILDER_PROMPT: &str = include_str!("builder.md");
pub(crate) const BUILDER_PROMPT_NORMAL: &str = include_str!("builder.normal.md");
pub(crate) const BUILDER_PROMPT_FRONTIER: &str = include_str!("builder.frontier.md");
pub(crate) const EXPLORE_PROMPT: &str = include_str!("explore.md");
pub(crate) const EXPLORE_PROMPT_NORMAL: &str = include_str!("explore.normal.md");
pub(crate) const DEEPTHINK_PROMPT: &str = include_str!("deepthink.md");
pub(crate) const SCOUT_PROMPT: &str = include_str!("scout.md");
pub(crate) const SCOUT_PROMPT_NORMAL: &str = include_str!("scout.normal.md");
pub(crate) const PLAN_PROMPT: &str = include_str!("plan.md");
pub(crate) const PLAN_PROMPT_NORMAL: &str = include_str!("plan.normal.md");
pub(crate) const SWARM_PROMPT: &str = include_str!("swarm.md");
pub(crate) const SWARM_PROMPT_NORMAL: &str = include_str!("swarm.normal.md");
pub(crate) const SWARM_PROMPT_FRONTIER: &str = include_str!("swarm.frontier.md");
pub(crate) const MULTIREVIEW_PROMPT: &str = include_str!("multireview.md");
pub(crate) const MULTIREVIEW_PROMPT_NORMAL: &str = include_str!("multireview.normal.md");
// `bee` — `Swarm`'s recursive parallel worker (GOALS §24/§26).
pub(crate) const BEE_PROMPT: &str = include_str!("bee.md");
pub(crate) const BEE_PROMPT_NORMAL: &str = include_str!("bee.normal.md");
pub(crate) const BEE_PROMPT_FRONTIER: &str = include_str!("bee.frontier.md");
const COMPUTER_PROMPT: &str = "You are the computer-use subagent. Use the provider-native computer tool to inspect and operate the display only for the delegated task. Report concise progress and stop when the delegated display work is complete.";

/// Select a bundled agent's prompt body for the active `llm_mode`: defensive
/// uses the flat body; normal uses the normal body when present; frontier uses
/// an explicit frontier body when present, else normal, else the flat body.
/// This mirrors [`crate::agents::AgentDef::resolved_prompt_for`].
fn builtin_prompt_for(
    defensive: &'static str,
    normal: Option<&'static str>,
    frontier: Option<&'static str>,
    mode: crate::config::extended::LlmMode,
) -> &'static str {
    use crate::config::extended::LlmMode;
    match mode {
        LlmMode::Defensive => defensive,
        LlmMode::Normal => normal.unwrap_or(defensive),
        LlmMode::Frontier => frontier.or(normal).unwrap_or(defensive),
    }
}
/// Docs pipeline stage prompts (GOALS §3a, prompt `docs-agent.md`).
const DOCS_RESOLVER_PROMPT: &str = include_str!("docs_resolver.md");
const DOCS_ANSWERER_PROMPT: &str = include_str!("docs_answerer.md");

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
    /// The active LLM-strength mode (implementation note).
    /// Threaded onto every spawned [`Agent`] so the centralized tool-
    /// description rendering seam ([`ToolBox::definitions`]) and the per-mode
    /// agent-prompt resolution ([`crate::agents::AgentDef::resolved_prompt_for`])
    /// both read one value. Resolved from the layered `config.json`
    /// at session start; live-switched via `/llm-mode`.
    pub llm_mode: crate::config::extended::LlmMode,
    /// Plan-level model override (prompt
    /// `plan-duplication-and-model-override.md`): when a plan pins a `model`,
    /// every agent spawned by that plan's run uses it, **overriding** even an
    /// agent's frontmatter `model` (precedence: plan → frontmatter → session).
    /// `None` outside a plan run, where the session model + frontmatter behave
    /// exactly as before. Resolved once when the session worker starts and
    /// threaded onto every spawn.
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
    let caps = providers.resolve_capabilities(model.provider_id(), model.model_id_ref());
    let native_computer = (tier != crate::config::extended::ComputerUseMode::Disabled
        && caps.images == Some(true))
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
    let providers = crate::config::providers::ConfigDoc::load_effective(&args.cwd);
    params.native_computer =
        resolved_computer_use_for_model(&providers, &args.cwd, model).native_computer;
    params
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
            let caps = providers.resolve_capabilities(provider_id, &model.id);
            if caps.images != Some(true) {
                continue;
            }
            let Some(contract) = caps.computer_use.and_then(|capability| capability.contract)
            else {
                continue;
            };
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

fn computer_subagent_reachable(cwd: &Path) -> bool {
    let providers = crate::config::providers::ConfigDoc::load_effective(cwd);
    computer_subagent_candidate(&providers, cwd).is_some()
}

/// Append the full codebase-intelligence tool set (GOALS §21) to `tb`.
/// Centralized so the write-capable agents (`Build`/`builder`/`Swarm`/`bee`)
/// and the deep-investigation primaries (`Plan`/`explore`) share one
/// definition of "full intel" rather than each re-spelling the intel tools.
fn with_full_intel(tb: ToolBox) -> ToolBox {
    tb.with(Arc::new(crate::tools::intel::ContextPackTool))
        .with(Arc::new(crate::tools::intel::TreeTool))
        .with(Arc::new(crate::tools::intel::OutlineTool))
        .with(Arc::new(crate::tools::intel::SymbolFindTool))
        .with(Arc::new(crate::tools::intel::WordTool))
        .with(Arc::new(crate::tools::intel::DepsTool))
        .with(Arc::new(crate::tools::intel::HotTool))
        .with(Arc::new(crate::tools::intel::CircularTool))
        .with(Arc::new(crate::tools::intel::SearchTool))
        .with(Arc::new(crate::tools::intel::ImpactTool))
        .with(Arc::new(crate::tools::intel::ChangeImpactTool))
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
    tb.with(Arc::new(crate::tools::readlock::ReadlockTool))
        .with(Arc::new(crate::tools::writeunlock::WriteunlockTool))
        .with(Arc::new(crate::tools::editunlock::EditunlockTool))
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
        .with(Arc::new(crate::tools::todo_read::TodoReadTool))
        .with(Arc::new(crate::tools::goal::CreateGoalTool))
        .with(Arc::new(crate::tools::goal::GetGoalTool))
        .with(Arc::new(crate::tools::goal::UpdateGoalTool))
}

fn with_task_for_targets(tb: ToolBox, args: &SpawnArgs, targets: &[&str]) -> ToolBox {
    let allowed: Vec<&str> = if args.delegated {
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
    if args.delegated {
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
        "tree",
        "outline",
        "symbol_find",
        "word",
        "deps",
        "hot",
        "circular",
        "search",
        "change_impact",
        "task",
        "skill",
        "skill_manage",
        "question",
        "schedule",
        "spawn",
        "handoff",
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
        "todo",
        "todo_read",
        "create_goal",
        "get_goal",
        "update_goal",
        "readlock",
        "writeunlock",
        "editunlock",
        "unlock",
        "grep",
        "glob",
    ]
}

fn extra_custom_tool_reserved_names() -> &'static [&'static str] {
    &[
        "seed",
        "list-packages",
        "add-package",
        "tool_result_retrieve",
        "delegation_payload_retrieve",
    ]
}

fn is_reserved_custom_tool_name(name: &str) -> bool {
    known_agent_tool_names().contains(&name) || extra_custom_tool_reserved_names().contains(&name)
}

fn validate_configured_custom_tools(cwd: &Path) -> Result<()> {
    let cfg = crate::config::extended::load_for_cwd(cwd);
    for name in cfg.tools.keys() {
        if crate::tools::custom::is_builtin_web_tool(name) {
            continue;
        }
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
        Arc::new(tools::readlock::ReadlockTool),
        Arc::new(tools::writeunlock::WriteunlockTool),
        Arc::new(tools::unlock::UnlockTool),
        Arc::new(tools::editunlock::EditunlockTool),
        Arc::new(tools::bash::BashTool::new()),
        Arc::new(tools::escalate::EscalateTool),
        Arc::new(tools::intel::ContextPackTool),
        Arc::new(tools::intel::TreeTool),
        Arc::new(tools::intel::OutlineTool),
        Arc::new(tools::intel::SymbolFindTool),
        Arc::new(tools::intel::WordTool),
        Arc::new(tools::intel::DepsTool),
        Arc::new(tools::intel::HotTool),
        Arc::new(tools::intel::CircularTool),
        Arc::new(tools::intel::SearchTool),
        Arc::new(tools::intel::ImpactTool),
        Arc::new(tools::intel::ChangeImpactTool),
        Arc::new(tools::skill::SkillTool),
        Arc::new(tools::skill_manage::SkillManageTool),
        Arc::new(tools::question::QuestionTool),
        Arc::new(tools::defer::DeferTool),
        Arc::new(tools::schedule::ScheduleTool),
        Arc::new(tools::mcp_tool::McpTool),
        Arc::new(tools::lsp::LspTool),
        Arc::new(tools::handoff::HandoffTool),
        Arc::new(tools::return_tool::ReturnTool),
        Arc::new(tools::plan_doc::PlanReadTool),
        Arc::new(tools::plan_doc::PlanWriteTool),
        Arc::new(tools::plan_doc::PlanEditTool),
        Arc::new(tools::plan_doc::StartBuildTool),
        Arc::new(tools::session_search::SessionSearchTool),
        Arc::new(tools::session_read::SessionReadTool),
        Arc::new(tools::todo::TodoTool),
        Arc::new(tools::todo_read::TodoReadTool),
        Arc::new(tools::tool_result_retrieve::ToolResultRetrieveTool),
        Arc::new(tools::delegation_payload_retrieve::DelegationPayloadRetrieveTool),
        Arc::new(tools::goal::CreateGoalTool),
        Arc::new(tools::goal::GetGoalTool),
        Arc::new(tools::goal::UpdateGoalTool),
        Arc::new(tools::grep::GrepTool),
        Arc::new(tools::glob::GlobTool),
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
        "bash" => tb.with(Arc::new(tools::bash::BashTool::new())),
        "escalate" => tb.with(Arc::new(tools::escalate::EscalateTool)),
        "readlock" => tb.with(Arc::new(tools::readlock::ReadlockTool)),
        "writeunlock" => tb.with(Arc::new(tools::writeunlock::WriteunlockTool)),
        "editunlock" => tb.with(Arc::new(tools::editunlock::EditunlockTool)),
        "unlock" => tb.with(Arc::new(tools::unlock::UnlockTool)),
        "context_pack" => tb.with(Arc::new(tools::intel::ContextPackTool)),
        "tree" => tb.with(Arc::new(tools::intel::TreeTool)),
        "outline" => tb.with(Arc::new(tools::intel::OutlineTool)),
        "symbol_find" => tb.with(Arc::new(tools::intel::SymbolFindTool)),
        "word" => tb.with(Arc::new(tools::intel::WordTool)),
        "deps" => tb.with(Arc::new(tools::intel::DepsTool)),
        "hot" => tb.with(Arc::new(tools::intel::HotTool)),
        "circular" => tb.with(Arc::new(tools::intel::CircularTool)),
        "search" => tb.with(Arc::new(tools::intel::SearchTool)),
        "change_impact" => tb.with(Arc::new(tools::intel::ChangeImpactTool)),
        "skill" => tb.with(Arc::new(tools::skill::SkillTool)),
        "skill_manage" => tb.with(Arc::new(tools::skill_manage::SkillManageTool)),
        "question" => tb.with(Arc::new(tools::question::QuestionTool)),
        "schedule" => tb.with(Arc::new(tools::schedule::ScheduleTool)),
        "mcp" => tb.with(Arc::new(tools::mcp_tool::McpTool)),
        "webfetch" | "websearch" => tb.with(tools::web::materialize_web_tool(name, &args.cwd)?),
        "lsp" => tb.with(Arc::new(tools::lsp::LspTool)),
        "handoff" => tb.with(Arc::new(tools::handoff::HandoffTool)),
        "return" => tb.with(Arc::new(tools::return_tool::ReturnTool)),
        "plan_read" => tb.with(Arc::new(tools::plan_doc::PlanReadTool)),
        "plan_write" => tb.with(Arc::new(tools::plan_doc::PlanWriteTool)),
        "plan_edit" => tb.with(Arc::new(tools::plan_doc::PlanEditTool)),
        "start_build" => tb.with(Arc::new(tools::plan_doc::StartBuildTool)),
        "todo" => tb.with(Arc::new(tools::todo::TodoTool)),
        "todo_read" => tb.with(Arc::new(tools::todo_read::TodoReadTool)),
        "create_goal" => tb.with(Arc::new(tools::goal::CreateGoalTool)),
        "get_goal" => tb.with(Arc::new(tools::goal::GetGoalTool)),
        "update_goal" => tb.with(Arc::new(tools::goal::UpdateGoalTool)),
        "defer_to_orchestrator" => tb.with(Arc::new(tools::defer::DeferTool)),
        "harness_list" => tb.with(Arc::new(tools::harness::HarnessListTool)),
        "harness_invoke" => tb.with(Arc::new(tools::harness::HarnessInvokeTool)),
        "session_search" => tb.with(Arc::new(tools::session_search::SessionSearchTool)),
        "session_read" => tb.with(Arc::new(tools::session_read::SessionReadTool)),
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
            let subs = reachable_subagents(def, &args.cwd);
            let sub_refs: Vec<&str> = subs.iter().map(String::as_str).collect();
            with_task_for_targets(tb, args, &sub_refs)
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

fn compose_system_prompt_for_effective_model(role_prompt: &str, args: &SpawnArgs) -> String {
    let model = args.effective_model();
    compose_system_prompt_for_model(role_prompt, &model, args)
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
    let os = crate::sysinfo::os_string();
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
/// append them to `tb`. Falls back to the shipped defaults for any built-in
/// tool name the user hasn't configured.
/// Disabled rows and empty commands are skipped.
fn with_custom_tools(mut tb: ToolBox, cwd: &Path) -> ToolBox {
    let cfg = crate::config::extended::load_for_cwd(cwd);
    let custom_web = cfg.web.provider == crate::config::extended::WebProvider::Custom;

    if !custom_web {
        tb = tb.with(Arc::new(crate::tools::web::WebFetchTool));
        tb = tb.with(Arc::new(crate::tools::web::WebSearchTool));
    }

    for (name, tpl) in cfg.tools.iter() {
        if !tpl.enabled || tpl.command.trim().is_empty() {
            continue;
        }
        if crate::tools::custom::is_builtin_web_tool(name) && !custom_web {
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
    for name in crate::tools::custom_templates::builtin_tool_names() {
        if crate::tools::custom::is_builtin_web_tool(name) && !custom_web {
            continue;
        }
        if cfg.tools.contains_key(*name) {
            continue;
        }
        let tpl: ToolCommandTemplate = crate::tools::custom_templates::default_template_for(name);
        if tpl.enabled && !tpl.command.trim().is_empty() {
            tb = tb.with(Arc::new(CustomBashTool::from_template_with_provenance(
                name,
                &tpl,
                ToolTemplateProvenance::ShippedDefault,
            )));
        }
    }
    tb
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
    validate_configured_custom_tools(&args.cwd)?;

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

    // Overlay: an on-disk override (edited built-in) or a custom agent
    // takes precedence over the embedded factory. A malformed override
    // fails loudly here (naming its source) rather than silently falling
    // back to the embedded default.
    let mut agent = match crate::agents::resolve(&args.cwd, name)? {
        // A genuine on-disk file (override of a built-in, or a custom
        // agent): build generically from the resolved definition so the
        // user's edited tools/model/prompt take effect.
        Some(def) if !def.source.as_os_str().is_empty() => agent_from_def(&def, args)?,
        // An embedded default came back (no override): use the hardcoded
        // factory, which is byte-identical and cache-stable.
        Some(_) => {
            let mut agent = match name {
                "Auto" => auto(args),
                "Build" => build(args),
                "builder" => builder(args),
                "explore" => explore(args),
                "deepthink" => deepthink(args),
                "scout" => scout(args),
                "Plan" => plan(args),
                "Swarm" => swarm(args),
                "bee" => bee(args),
                "Multireview" => multireview(args),
                other => bail!("unknown built-in agent `{other}`"),
            };
            let def = crate::agents::embedded_default(name)
                .expect("resolved embedded built-in must have embedded default");
            agent.model = resolve_agent_model(&def, args)?;
            agent.system = compose_system_prompt_for_model(&agent.role_prompt, &agent.model, args);
            agent
        }
        // Not a built-in and no file on disk: unknown agent.
        None => bail!("unknown agent `{name}`"),
    };

    // Per-delegation tool grants (prompt `parent-granted-tools.md`): append the
    // parent's granted tools onto the just-built base surface, for this run
    // only. The grant was already validated against the role invariants in the
    // driver before the spawn; this only materializes the named tools. A child
    // is a fresh context, so its tool set (base + grants) is fixed here at spawn
    // — the cache-safety rule holds per child-run, and grants can't persist or
    // leak because each spawn passes a fresh `SpawnArgs.granted_tools`.
    if !args.granted_tools.is_empty() && name != "deepthink" {
        agent.tools = apply_grants(agent.tools, &args.granted_tools, args)?;
    }
    agent.params = params_with_direct_computer(args, &agent.model);
    Ok(agent)
}

/// Append the parent-granted tools onto a built agent's base toolbox (prompt
/// `parent-granted-tools.md`). Only non-structural, non-delegation tools are
/// grantable (the delegation/handoff tools are rejected up front by
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
/// - it is a leaf — it holds no `task`/`handoff` (it delegates to no one;
///   re-querying must not grant a subagent new delegation powers,
///   leaf-termination, GOALS §3c).
///
/// Today this is `explore` (and any custom read-only leaf subagent); a future
/// read-only noninteractive leaf subagent qualifies automatically. A primary
/// (`Build`/`Plan`/`Auto`) is excluded by the leaf check — it holds `task` /
/// `handoff` — and is never delegated to via `task` anyway.
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

/// True when `agent` holds a delegation/handoff tool (`task`/`handoff`) — it is
/// not a leaf. Used to keep the read-only-leaf scope tight.
fn is_delegating(agent: &Agent) -> bool {
    let names = agent.tools.names();
    names.contains(&"task") || names.contains(&"handoff")
}

/// Register the structural `return` tool on `tb` for a **delegated subagent**
/// (implementation note). Every delegated subagent
/// — `builder`/`explore` and any custom subagent — finishes by
/// returning a structured summary envelope, so it holds `return` from session
/// start (cache-safe; the tools array is never mutated mid-session). The `docs`
/// pipeline stages are **exempt** (their answer is the payload), so they never
/// get it; a chat-owning primary (`Auto`/`Build`/`Plan`/`Swarm`) is never
/// delegated to and finishes via `Done`/`handoff`/`done`, so it is excluded
/// too. `name` is the agent's own name.
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
/// never delegated to and finishes via `Done`/`handoff`.
fn is_primary(name: &str) -> bool {
    matches!(name, "Auto" | "Build" | "Plan" | "Swarm")
}

/// Register the `seed` tool (GOALS §3c) on `tb` when this is a read-only
/// noninteractive subagent spawned in `normal` mode. The capability is gated
/// at the engine's point of action ([`crate::engine::tool::Capability`]); the
/// tool surface follows the same gate so a `defensive`-mode subagent never
/// even sees `seed`. `name` is the agent's own name; the read-only check
/// against the lock/write tools is done on `tb` as it stands.
fn maybe_with_seed_tool(
    tb: ToolBox,
    name: &str,
    llm_mode: crate::config::extended::LlmMode,
) -> ToolBox {
    use crate::engine::tool::Capability;
    if !Capability::FollowupSeed.enabled(llm_mode)
        || !is_noninteractive(name)
        || is_docs_pipeline(name)
    {
        return tb;
    }
    let names = tb.names();
    let writes = crate::agents::invariants::LOCK_WRITE_TOOLS
        .iter()
        .any(|w| names.contains(w));
    if writes {
        return tb;
    }
    tb.with(Arc::new(crate::tools::seed::SeedEmitTool))
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
fn agent_from_def(def: &crate::agents::AgentDef, args: &SpawnArgs) -> Result<Agent> {
    if def.name == "deepthink" {
        let model = resolve_agent_model(def, args)?;
        let mut params = args.params.clone();
        if let Some(temp) = def.temperature {
            params.temperature = Some(temp as f64);
        }
        let role = def.resolved_prompt_for(args.llm_mode);
        return Ok(Agent {
            name: def.name.clone(),
            system: compose_system_prompt_for_model(role, &model, args),
            role_prompt: role.to_string(),
            tools: ToolBox::new(),
            model,
            params,
            scan_tool_results: false,
            llm_mode: args.llm_mode,
            delegated: args.delegated,
            delegation_recursion: DelegationRecursionContext {
                enabled: args.delegation_recursion.enabled,
                remaining_depth: 0,
                allowed_targets: Vec::new(),
                same_model_only: false,
            },
            env_overlay: args.env_overlay.clone(),
        });
    }

    // Resolve the tool-name grant: explicit list, else the role default.
    let grant: Vec<String> = match &def.tools {
        Some(t) => t.clone(),
        None => crate::agents::embedded_default(&def.name)
            .and_then(|d| d.tools)
            .unwrap_or_else(default_custom_tools),
    };

    let mut tb = ToolBox::new();
    for name in &grant {
        tb = add_tool_by_name(tb, name, def, args)?;
    }
    // Custom-bash tools (webfetch/websearch/…) are config-driven, not part
    // of the named grant — attach them like the built-in factories do.
    tb = with_custom_tools(tb, &args.cwd);
    // Cross-session recall tools, gated on interactive spawn.
    tb = with_recall_tools(tb, args);
    // `seed` (GOALS §3c): a custom read-only noninteractive subagent in
    // normal mode may emit seeds to its caller. The helper re-checks the
    // (now-built) tool surface for write/lock tools, so only a genuinely
    // read-only custom subagent gets it.
    tb = maybe_with_seed_tool(tb, &def.name, args.llm_mode);
    // `return` (structured-summary envelope, `structured-subagent
    // -return-summary.md`): a delegated subagent finishes by returning a
    // structured summary. An on-disk override of a bundled agent keeps its name,
    // so `with_return_tool`'s name guards exclude a bundled primary/docs
    // override; a custom agent is gated on its `mode` here (a `Primary`-only
    // custom agent is chat-owning, never delegated to, so it gets no `return`).
    if crate::agents::embedded_default(&def.name).is_some() || def.mode.is_subagent() {
        tb = with_return_tool(tb, &def.name);
    }
    // Per-agent tool-description overrides (prompt
    // `per-agent-tool-definitions.md`): re-word a granted tool's description
    // for this markdown agent. Applied last so it lands on whatever tool of
    // that name is on the box; the schema is never touched, so the tools array
    // stays byte-stable for `(agent, mode)`. Naming a non-granted tool was
    // rejected at load (`validate_invariants`), so an override here always has
    // a matching tool.
    for (tool_name, spec) in &def.tool_descriptions {
        tb = tb.with_override(tool_name, spec.to_override());
    }

    // Model precedence (plan → frontmatter → caller choice → role slot →
    // session). A malformed explicit frontmatter selector fails loudly because
    // it is a direct user setting; unset or unconfigured role slots fall back.
    let model = resolve_agent_model(def, args)?;

    let mut params = args.params.clone();
    if let Some(temp) = def.temperature {
        params.temperature = Some(temp as f64);
    }

    let role = def.resolved_prompt_for(args.llm_mode);
    Ok(Agent {
        name: def.name.clone(),
        system: compose_system_prompt_for_model(role, &model, args),
        role_prompt: role.to_string(),
        tools: tb,
        model,
        params,
        scan_tool_results: def
            .scan_tool_results
            .unwrap_or_else(|| crate::agents::default_scan_tool_results(&def.name, def.mode)),
        llm_mode: args.llm_mode,
        delegated: args.delegated,
        delegation_recursion: args.delegation_recursion.clone(),
        env_overlay: args.env_overlay.clone(),
    })
}

/// Default tool grant for a custom agent that names no `tools:` — the
/// read-only investigator surface (`explore`'s grant). Conservative:
/// never includes write/lock or structural-delegation tools.
fn default_custom_tools() -> Vec<String> {
    [
        "read",
        "bash",
        "tree",
        "outline",
        "symbol_find",
        "word",
        "deps",
        "hot",
        "circular",
        "search",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
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
fn reachable_subagents(def: &crate::agents::AgentDef, cwd: &Path) -> Vec<String> {
    let mut out = if def.name == "Plan" {
        plan_subagents(cwd)
    } else {
        build_subagents(cwd)
    };
    out.retain(|s| *s != def.name);
    out
}

/// The bundled reachable subagent set for `Plan` plus any user-authored
/// custom subagent (`mode` `subagent`/`all`).
fn plan_subagents(cwd: &Path) -> Vec<String> {
    let mut out: Vec<String> = vec!["explore".to_string()];
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
fn build_subagents(cwd: &Path) -> Vec<String> {
    let mut out: Vec<String> = vec![
        "builder".to_string(),
        "explore".to_string(),
        "docs".to_string(),
    ];
    if computer_subagent_reachable(cwd) {
        out.push("computer".to_string());
    }
    if load_extended_config(cwd).deepthink.enabled {
        out.push("deepthink".to_string());
    }
    append_custom_subagents(&mut out, cwd);
    out
}

fn add_deepthink_if_enabled(out: &mut Vec<String>, cwd: &Path) {
    if load_extended_config(cwd).deepthink.enabled && !out.iter().any(|name| name == "deepthink") {
        out.push("deepthink".to_string());
    }
}

fn recursive_targets(cwd: &Path, base: &[&str]) -> Vec<String> {
    let mut out = base
        .iter()
        .map(|target| target.to_string())
        .collect::<Vec<_>>();
    add_deepthink_if_enabled(&mut out, cwd);
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
            && custom.mode.is_subagent()
            && !out.contains(&listing.name)
        {
            out.push(listing.name);
        }
    }
}

/// Resolve the model an agent spawns under.
fn resolve_agent_model(def: &crate::agents::AgentDef, args: &SpawnArgs) -> Result<Arc<Model>> {
    // A plan-level model overrides the frontmatter entirely.
    if let Some(model) = &args.model_override {
        return Ok(model.clone());
    }
    let (extended, providers) = crate::engine::model_roles::load_model_role_config(&args.cwd);
    match crate::engine::model_roles::resolve_delegated_model(
        &def.name,
        def.model.as_deref(),
        args.delegation_model.as_ref(),
        &extended,
        &providers,
        &args.model,
    ) {
        Ok(model) => Ok(model),
        Err(crate::engine::model_roles::SelectorResolution::InvalidLiteral(message)) => {
            bail!("invalid explicit subagent model selector: {message}")
        }
        Err(crate::engine::model_roles::SelectorResolution::Unset) => Ok(args.model.clone()),
    }
}

/// `Auto` — the default front-door primary. Converses, answers plain
/// questions directly, and hands off to `Plan`/`Build` via the structural
/// `handoff` tool once the user's intent is clear (the spec's router).
/// Holds no write/lock or delegation tools — the chosen primary owns the
/// work after the swap.
pub fn auto(args: &SpawnArgs) -> Agent {
    let tools = with_recall_tools(
        with_custom_tools(
            ToolBox::new()
                .with(Arc::new(crate::tools::read::ReadTool))
                .with(Arc::new(crate::tools::bash::BashTool::new()))
                // `search` (GOALS §21): a light, budgeted structured search so
                // the router can answer a quick "where is X" without delegating.
                .with(Arc::new(crate::tools::intel::SearchTool))
                // `question` (GOALS §3b): blocks the turn until the user
                // disambiguates — the router's clarifying-exchange path.
                .with(Arc::new(crate::tools::skill::SkillTool))
                .with(Arc::new(crate::tools::question::QuestionTool))
                // `handoff` (structural): the engine routes the chosen
                // target to the driver's single primary-swap authority.
                .with(Arc::new(crate::tools::handoff::HandoffTool))
                // MCP (GOALS §18a): `mcp` runs the Monty Python sandbox.
                .with(Arc::new(crate::tools::mcp_tool::McpTool)),
            &args.cwd,
        ),
        args,
    );

    let role = builtin_prompt_for(AUTO_PROMPT, Some(AUTO_PROMPT_NORMAL), None, args.llm_mode);
    Agent {
        name: "Auto".to_string(),
        system: compose_system_prompt_for_effective_model(role, args),
        role_prompt: role.to_string(),
        tools,
        model: args.effective_model(),
        params: args.params.clone(),
        scan_tool_results: true,
        llm_mode: args.llm_mode,
        delegated: args.delegated,
        delegation_recursion: args.delegation_recursion.clone(),
        env_overlay: args.env_overlay.clone(),
    }
}

/// `Build` — the user-facing, **write-capable** primary agent. Owns the chat
/// when the focus is *making the change* (GOALS §3a). It can write directly
/// (it holds the lock/write tools, arbitrated by the single lock authority),
/// but its intent is **delegate-eager**: hand substantive feature work to
/// `builder` via `task` and direct-write only small single-scope changes.
pub fn build(args: &SpawnArgs) -> Agent {
    // Reachable subagents: the bundled set plus any custom subagent the
    // user has added (implementation note discoverability).
    let subs = build_subagents(&args.cwd);
    let sub_refs: Vec<&str> = subs.iter().map(String::as_str).collect();
    let base_tools = with_write_tools(with_full_intel(
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
            &args.cwd,
        ),
        args,
    );
    // Per-agent intent (prompt `per-agent-tool-definitions.md`): `Build` is
    // delegate-eager — substantive feature work and follow-up implementation
    // iterations go to fresh `builder` tasks, while `Build` decides, briefs,
    // and reports. The override re-words only the description for this agent;
    // the tool ID + schema are unchanged, so the tools array stays byte-stable
    // for `(Build, mode)`.
    let tools = tools.with_override(
        "task",
        crate::engine::tool::ToolDescOverride {
            normal: Some(
                "Delegate substantive feature work to a subagent (builder writes, explore investigates); if task returns backgrounded JSON, the call is closed but the child is detached/result-pending, so use task_call_id controls or the async result rather than duplicate work; use docs by default for unfamiliar or version-sensitive dependency APIs"
                    .to_string(),
            ),
            frontier: Some(
                "Write small local edits directly; delegate larger, multi-file, risky, or isolated work to builder/explore; backgrounded JSON means the task call closed but the child is detached/result-pending; use docs when APIs are unfamiliar or version-sensitive"
                    .to_string(),
            ),
            defensive: Some(
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

    let role = builtin_prompt_for(
        BUILD_PROMPT,
        Some(BUILD_PROMPT_NORMAL),
        Some(BUILD_PROMPT_FRONTIER),
        args.llm_mode,
    );
    let model = args.effective_model();
    let params = params_with_direct_computer(args, &model);
    Agent {
        name: "Build".to_string(),
        system: compose_system_prompt_for_effective_model(role, args),
        role_prompt: role.to_string(),
        tools,
        model,
        params,
        scan_tool_results: true,
        llm_mode: args.llm_mode,
        delegated: args.delegated,
        delegation_recursion: args.delegation_recursion.clone(),
        env_overlay: args.env_overlay.clone(),
    }
}

/// `builder` — a **write-capable** worker subagent. Holds file locks; runs
/// bash; applies edits. Its surface mirrors `Build`'s write + full-intel +
/// bash + skill + MCP + web, **minus** general feature-delegation: it
/// keeps `task` only to reach the `docs` pipeline and has no `schedule`. Intent:
/// **do-it-yourself** within its scope; return out-of-scope work up via the
/// structured-return envelope. Caller-determined interactivity: interactive
/// when spawned from `Build` (GOALS §3a/§3b).
pub fn builder(args: &SpawnArgs) -> Agent {
    let recursive_targets = recursive_targets(&args.cwd, &["docs"]);
    let recursive_refs: Vec<&str> = recursive_targets.iter().map(String::as_str).collect();
    let base_tools = with_write_tools(with_full_intel(
        ToolBox::new()
            .with(Arc::new(crate::tools::read::ReadTool))
            .with(Arc::new(crate::tools::bash::BashTool::new())),
    ))
    // `question` (GOALS §3b): blocks the turn until the user answers.
    .with(Arc::new(crate::tools::question::QuestionTool))
    // `skill` (GOALS §5): manual on-demand skill loading.
    .with(Arc::new(crate::tools::skill::SkillTool))
    // MCP (GOALS §18a): Monty Python sandbox.
    .with(Arc::new(crate::tools::mcp_tool::McpTool));
    let tools = with_recall_tools(
        with_custom_tools(
            // `builder` may receive recursive delegation affordances only
            // when its spawn context has remaining budget.
            with_task_for_targets(base_tools, args, &recursive_refs),
            &args.cwd,
        ),
        args,
    );
    // Per-agent intent (prompt `per-agent-tool-definitions.md`): `builder` is
    // do-it-yourself — its only `task` target is the `docs` pipeline, so the
    // override frames `task` as "look up a dependency's usage", never general
    // delegation. The override re-words only the description; the schema is
    // unchanged.
    let tools = tools.with_override(
        "task",
        crate::engine::tool::ToolDescOverride {
            normal: Some(
                "Use `task` only for docs by default for unfamiliar APIs; if docs backgrounds, the call is closed but detached/result-pending, so use the async result or task_call_id controls rather than guess or retry; otherwise do the assigned code work yourself"
                    .to_string(),
            ),
            frontier: Some(
                "Use `task` only for docs when APIs are unfamiliar; if docs backgrounds, the call is closed but detached/result-pending, so use the async result or task_call_id controls rather than guess or retry; otherwise do the assigned code work yourself"
                    .to_string(),
            ),
            defensive: Some(
                "Do the assigned code work yourself — read, lock, edit, and verify in this context. \
                 Use `task` only to ask the `docs` pipeline how a third-party dependency's API \
                 works — and when you need that API, asking `docs` is your first move, not a guess \
                 or a web search, unless the exact usage pattern is clearly established in \
                 already-read local code: a source-cited answer is worth the tokens. Do exactly \
                 one assigned implementation slice. Do not try to delegate the feature itself or \
                 accept new feature work outside the brief. If the request turns out to be out of \
                 your assigned scope, return the out-of-scope ask to your caller via the structured \
                 `return` report rather than expanding it. If a docs task returns backgrounded \
                 task_delegation JSON, the call is closed but detached/result-pending; wait for \
                 the async result or query/list/status by task_call_id, and read child status/error \
                 because docs can fail, be cancelled, or be lost."
                    .to_string(),
            ),
        },
    );
    // `return` (structured-summary envelope): `builder` is a delegated subagent,
    // so it finishes by reporting a structured summary to its caller.
    let tools = with_return_tool(tools, "builder");

    let role = builtin_prompt_for(
        BUILDER_PROMPT,
        Some(BUILDER_PROMPT_NORMAL),
        Some(BUILDER_PROMPT_FRONTIER),
        args.llm_mode,
    );
    Agent {
        name: "builder".to_string(),
        system: compose_system_prompt_for_effective_model(role, args),
        role_prompt: role.to_string(),
        tools,
        model: args.effective_model(),
        params: args.params.clone(),
        scan_tool_results: true,
        llm_mode: args.llm_mode,
        delegated: args.delegated,
        delegation_recursion: args.delegation_recursion.clone(),
        env_overlay: args.env_overlay.clone(),
    }
}

/// `explore` — read-only investigator. Leaf in the invocation tree
/// (no `task` of its own). Runs noninteractively from
/// `Build`'s perspective: the primary agent dispatches it
/// via `task(agent="explore", …)` and gets a single text report back
/// as the tool result. The user sees the call rendered like any other
/// tool in the primary agent's history.
pub fn explore(args: &SpawnArgs) -> Agent {
    let recursive_targets = recursive_targets(&args.cwd, &["explore"]);
    let recursive_refs: Vec<&str> = recursive_targets.iter().map(String::as_str).collect();
    let base_tools = with_lsp_nav(with_full_intel(
        ToolBox::new()
            .with(Arc::new(crate::tools::read::ReadTool))
            .with(Arc::new(crate::tools::bash::BashTool::new())),
    ));
    let base_tools = if args.delegated {
        with_task_for_targets(base_tools, args, &recursive_refs)
    } else {
        base_tools
    };
    let tools = with_recall_tools(with_custom_tools(base_tools, &args.cwd), args);
    // `seed` (GOALS §3c): only on a read-only noninteractive subagent in
    // normal mode. Gated by the behavioral capability check, not just the
    // description text.
    let tools = maybe_with_seed_tool(tools, "explore", args.llm_mode);
    // `return` (structured-summary envelope): `explore` is a delegated subagent.
    // Its `files_changed` self-empties — it issues no write/edit/unlock calls.
    let tools = with_return_tool(tools, "explore");

    let role = builtin_prompt_for(
        EXPLORE_PROMPT,
        Some(EXPLORE_PROMPT_NORMAL),
        None,
        args.llm_mode,
    );
    Agent {
        name: "explore".to_string(),
        system: compose_system_prompt_for_effective_model(role, args),
        role_prompt: role.to_string(),
        tools,
        model: args.effective_model(),
        params: args.params.clone(),
        scan_tool_results: false,
        llm_mode: args.llm_mode,
        delegated: args.delegated,
        delegation_recursion: args.delegation_recursion.clone(),
        env_overlay: args.env_overlay.clone(),
    }
}

/// `deepthink` — optional tool-free reasoning worker. It is intentionally a
/// leaf: no read/bash/MCP/custom tools, no `return`, no recursive `task`, and
/// no grant application. It receives only the caller-authored brief plus
/// explicit seeds already materialized by the delegation path.
pub fn deepthink(args: &SpawnArgs) -> Agent {
    Agent {
        name: "deepthink".to_string(),
        system: compose_system_prompt_for_effective_model(DEEPTHINK_PROMPT, args),
        role_prompt: DEEPTHINK_PROMPT.to_string(),
        tools: ToolBox::new(),
        model: args.effective_model(),
        params: args.params.clone(),
        scan_tool_results: false,
        llm_mode: args.llm_mode,
        delegated: args.delegated,
        delegation_recursion: DelegationRecursionContext {
            enabled: args.delegation_recursion.enabled,
            remaining_depth: 0,
            allowed_targets: Vec::new(),
            same_model_only: false,
        },
        env_overlay: args.env_overlay.clone(),
    }
}

/// `computer` — provider-native computer-use worker. It never inherits a
/// non-vision parent model: the factory selects an eligible
/// vision-capable, subagent-invokable model with a native computer contract
/// and refuses loudly when none exists.
pub fn computer(args: &SpawnArgs) -> Result<Agent> {
    let providers = crate::config::providers::ConfigDoc::load_effective(&args.cwd);
    let Some((provider_id, model_id, native_computer)) =
        computer_subagent_candidate(&providers, &args.cwd)
    else {
        bail!(
            "computer-use subagent requires a configured vision-capable, subagent-invokable model with native computer_use enabled"
        );
    };
    let model = Arc::new(crate::engine::model::Model::for_provider_trusted_only(
        &providers,
        &provider_id,
        &model_id,
        args.effective_model().session_redact_table(),
        args.effective_model().trusted_only_flag(),
    )?);
    let caps = providers.resolve_capabilities(model.provider_id(), model.model_id_ref());
    if caps.images != Some(true) {
        bail!(
            "computer-use subagent requires a vision-capable model; `{}`:`{}` is not vision-capable",
            model.provider_id(),
            model.model_id_ref()
        );
    }
    let mut params = args.params.clone();
    params.native_computer = Some(native_computer);
    Ok(Agent {
        name: "computer".to_string(),
        system: compose_system_prompt_for_model(COMPUTER_PROMPT, &model, args),
        role_prompt: COMPUTER_PROMPT.to_string(),
        tools: with_return_tool(ToolBox::new(), "computer"),
        model,
        params,
        scan_tool_results: false,
        llm_mode: args.llm_mode,
        delegated: args.delegated,
        delegation_recursion: DelegationRecursionContext {
            enabled: args.delegation_recursion.enabled,
            remaining_depth: 0,
            allowed_targets: Vec::new(),
            same_model_only: false,
        },
        env_overlay: args.env_overlay.clone(),
    })
}

/// `scout` — read-only recursive review worker. Its base surface mirrors
/// `explore` plus `spawn` and `return`; it holds no write/lock tools, no
/// `task`, no MCP, and no docs-only grep/glob. Used by the hidden
/// `Multireview` primary and by deeper scout recursion.
pub fn scout(args: &SpawnArgs) -> Agent {
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
            &args.cwd,
        ),
        args,
    );
    let tools = with_return_tool(tools, "scout");

    let role = builtin_prompt_for(SCOUT_PROMPT, Some(SCOUT_PROMPT_NORMAL), None, args.llm_mode);
    Agent {
        name: "scout".to_string(),
        system: compose_system_prompt_for_effective_model(role, args),
        role_prompt: role.to_string(),
        tools,
        model: args.effective_model(),
        params: args.params.clone(),
        scan_tool_results: false,
        llm_mode: args.llm_mode,
        delegated: args.delegated,
        delegation_recursion: args.delegation_recursion.clone(),
        env_overlay: args.env_overlay.clone(),
    }
}

/// `Plan` — the user-facing read-only planning agent. It investigates the
/// project, keeps a session-scoped virtual plan document, and hands the final
/// standalone plan to a fresh `Build` session when the user agrees. It holds no
/// filesystem write or lock tools.
pub fn plan(args: &SpawnArgs) -> Agent {
    let base_tools = with_lsp_nav(with_full_intel(
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
            &args.cwd,
        ),
        args,
    );

    let role = builtin_prompt_for(PLAN_PROMPT, Some(PLAN_PROMPT_NORMAL), None, args.llm_mode);
    Agent {
        name: "Plan".to_string(),
        system: compose_system_prompt_for_effective_model(role, args),
        role_prompt: role.to_string(),
        tools,
        model: args.effective_model(),
        params: args.params.clone(),
        scan_tool_results: true,
        llm_mode: args.llm_mode,
        delegated: args.delegated,
        delegation_recursion: args.delegation_recursion.clone(),
        env_overlay: args.env_overlay.clone(),
    }
}

/// `Swarm` — the interactive, **write-capable** recursive fan-out primary
/// (GOALS §24/§26). Its surface is `Build`'s entire surface (read/bash/full
/// intel/schedule/question/skill/task/MCP/web + the lock/write tools) plus
/// the extra `spawn` tool, which recursively fans out parallel background
/// `bee` workers. This is the **sole** documented exception to leaf-
/// termination: `Swarm`/`bee` may fan out `bee`, but still not
/// `Plan`/`Build`/etc. The recursive-spawn description carries the per-task
/// effective depth (`args.swarm_depth`) and the ceiling so the model can
/// self-limit. A spawn over the ceiling is refused by the driver and the
/// branch does the work itself (clamp, don't crash). Intent: general parallel
/// fan-out for any wide task, not just research.
pub fn swarm(args: &SpawnArgs) -> Agent {
    let subs = build_subagents(&args.cwd);
    let sub_refs: Vec<&str> = subs.iter().map(String::as_str).collect();
    let base_tools = with_write_tools(with_full_intel(
        ToolBox::new()
            .with(Arc::new(crate::tools::read::ReadTool))
            .with(Arc::new(crate::tools::bash::BashTool::new())),
    ))
    .with(Arc::new(crate::tools::schedule::ScheduleTool))
    .with(Arc::new(crate::tools::question::QuestionTool))
    .with(Arc::new(crate::tools::skill::SkillTool))
    // Swarm is itself write-capable, so `/learn` can persist through the
    // same guarded skill mutation service without an impossible handoff.
    .with(Arc::new(crate::tools::skill_manage::SkillManageTool))
    .with(Arc::new(crate::tools::harness::HarnessListTool))
    .with(Arc::new(crate::tools::harness::HarnessInvokeTool))
    // MCP (GOALS §18a): Monty Python sandbox.
    .with(Arc::new(crate::tools::mcp_tool::McpTool));
    let tools = with_recall_tools(
        with_custom_tools(
            with_task_for_targets(base_tools, args, &sub_refs)
                // The recursive fan-out tool (GOALS §24). Structural:
                // intercepted by the engine and routed to the driver's single
                // async-job authority, which enforces depth + global
                // concurrency. The description bakes in the per-task depth so
                // the model self-limits. Only `Swarm`/`bee` hold it.
                .with(Arc::new(crate::tools::spawn::SpawnTool::for_depth(
                    args.swarm_depth,
                    args.swarm_max_depth,
                ))),
            &args.cwd,
        ),
        args,
    );

    let role = builtin_prompt_for(
        SWARM_PROMPT,
        Some(SWARM_PROMPT_NORMAL),
        Some(SWARM_PROMPT_FRONTIER),
        args.llm_mode,
    );
    let model = args.effective_model();
    let params = params_with_direct_computer(args, &model);
    Agent {
        name: "Swarm".to_string(),
        system: compose_system_prompt_for_effective_model(role, args),
        role_prompt: role.to_string(),
        tools,
        model,
        params,
        scan_tool_results: true,
        llm_mode: args.llm_mode,
        delegated: args.delegated,
        delegation_recursion: args.delegation_recursion.clone(),
        env_overlay: args.env_overlay.clone(),
    }
}

/// `Multireview` — hidden read-only primary reached only by `/multireview`.
/// Orchestrates `scout` fan-out and isolated harness reviewers, then returns a
/// single consolidated analysis. No write/lock tools.
pub fn multireview(args: &SpawnArgs) -> Agent {
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
            .with(Arc::new(crate::tools::question::QuestionTool)),
            &args.cwd,
        ),
        args,
    );

    let role = builtin_prompt_for(
        MULTIREVIEW_PROMPT,
        Some(MULTIREVIEW_PROMPT_NORMAL),
        None,
        args.llm_mode,
    );
    Agent {
        name: "Multireview".to_string(),
        system: compose_system_prompt_for_effective_model(role, args),
        role_prompt: role.to_string(),
        tools,
        model: args.effective_model(),
        params: args.params.clone(),
        scan_tool_results: true,
        llm_mode: args.llm_mode,
        delegated: args.delegated,
        delegation_recursion: args.delegation_recursion.clone(),
        env_overlay: args.env_overlay.clone(),
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
    let recursive_targets = recursive_targets(&args.cwd, &["docs"]);
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
            &args.cwd,
        ),
        args,
    );
    // `return` (structured-summary envelope): `bee` is a delegated worker, so it
    // finishes by reporting a compact structured summary (+ a pointer to its
    // dedicated output) up to its parent.
    let tools = with_return_tool(tools, "bee");

    let role = builtin_prompt_for(
        BEE_PROMPT,
        Some(BEE_PROMPT_NORMAL),
        Some(BEE_PROMPT_FRONTIER),
        args.llm_mode,
    );
    Agent {
        name: "bee".to_string(),
        system: compose_system_prompt_for_effective_model(role, args),
        role_prompt: role.to_string(),
        tools,
        model: args.effective_model(),
        params: args.params.clone(),
        scan_tool_results: true,
        llm_mode: args.llm_mode,
        delegated: args.delegated,
        delegation_recursion: args.delegation_recursion.clone(),
        env_overlay: args.env_overlay.clone(),
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
) -> Agent {
    let tools = with_custom_tools(
        ToolBox::new()
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
            )))
            .with(Arc::new(crate::tools::bash::BashTool::new())),
        &args.cwd,
    );

    Agent {
        name: "docs-resolver".to_string(),
        system: compose_system_prompt_for_effective_model(DOCS_RESOLVER_PROMPT, args),
        role_prompt: DOCS_RESOLVER_PROMPT.to_string(),
        tools,
        model: args.effective_model(),
        params: args.params.clone(),
        scan_tool_results: true,
        llm_mode: args.llm_mode,
        delegated: args.delegated,
        delegation_recursion: args.delegation_recursion.clone(),
        env_overlay: args.env_overlay.clone(),
    }
}

/// Docs.2 — the answerer stage of the `docs` pipeline. Runs in the
/// resolved package directory (`args.cwd` is the package root). Tools:
/// `read` + the sandboxed `grep`/`glob` only — **no bash, no network, no
/// write** (prompt `docs-agent.md` decision 2/3). The sandbox confines
/// every path to `args.cwd`, which is why bash can be denied: Docs.2 runs
/// inside untrusted third-party source.
pub fn docs_answerer(args: &SpawnArgs) -> Agent {
    let tools = ToolBox::new()
        .with(Arc::new(crate::tools::read::ReadTool))
        .with(Arc::new(crate::tools::grep::GrepTool))
        .with(Arc::new(crate::tools::glob::GlobTool));

    Agent {
        name: "docs-answerer".to_string(),
        system: compose_system_prompt_for_effective_model(DOCS_ANSWERER_PROMPT, args),
        role_prompt: DOCS_ANSWERER_PROMPT.to_string(),
        tools,
        model: args.effective_model(),
        params: args.params.clone(),
        scan_tool_results: false,
        llm_mode: args.llm_mode,
        delegated: args.delegated,
        delegation_recursion: args.delegation_recursion.clone(),
        env_overlay: args.env_overlay.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::extended::ExtendedConfig;

    /// A keyless localhost model + [`SpawnArgs`] for exercising the agent
    /// factories. The model is never actually called — these tests only
    /// inspect the constructed agent's name + tool surface.
    fn test_spawn_args(cwd: &Path) -> SpawnArgs {
        test_spawn_args_with_provider_can_delegate(cwd, None)
    }

    fn test_spawn_args_with_provider_can_delegate(
        cwd: &Path,
        can_delegate: Option<bool>,
    ) -> SpawnArgs {
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
            session_short_id: String::new(),
            assistant_identity_prefix: None,
            model_system_prompt_snapshot: Arc::new(ModelSystemPromptSnapshot::empty()),
            interactive: true,
            llm_mode: crate::config::extended::LlmMode::default(),
            model_override: None,
            delegation_model: None,
            delegated: false,
            delegation_recursion: DelegationRecursionContext::default(),
            swarm_depth: 0,
            swarm_max_depth: crate::config::extended::DEFAULT_SWARM_MAX_DEPTH,
            granted_tools: Vec::new(),
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
        task_definition(agent, crate::config::extended::LlmMode::Normal).parameters["properties"]
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
        for name in ["read", "readlock", "task", "handoff", "seed"] {
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
        let agent = docs_answerer(&test_spawn_args(tmp.path()));
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
            "readlock",
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
        let task = task_definition(&build(&args), crate::config::extended::LlmMode::Normal);
        let targets = task.parameters["properties"]["payload"]["properties"]["agent"]["enum"]
            .as_array()
            .unwrap()
            .clone();
        assert!(!targets.iter().any(|value| value == "deepthink"));

        write_project_config(tmp.path(), r#"{"deepthink":{"enabled":true}}"#);
        let task = task_definition(&build(&args), crate::config::extended::LlmMode::Normal);
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
                            "images": false,
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
                        "capabilities": { "images": false }
                    },
                    {
                        "id": "vision",
                        "subagent_invokable": true,
                        "capabilities": {
                            "images": true,
                            "computer_use": { "contract": "open_ai_responses" }
                        }
                    }
                ]
            }"#,
        );
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
                        "capabilities": { "images": false }
                    },
                    {
                        "id": "vision",
                        "subagent_invokable": true,
                        "capabilities": {
                            "images": true,
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
                        "capabilities": { "images": false }
                    },
                    {
                        "id": "vision",
                        "subagent_invokable": true,
                        "capabilities": {
                            "images": true,
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
                            "images": true,
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
    fn auto_factory_routes_no_writes_no_delegation() {
        let tmp = tempfile::tempdir().unwrap();
        let agent = auto(&test_spawn_args(tmp.path()));
        assert_eq!(agent.name, "Auto");
        let names = agent.tools.names();
        // The front-door router converses + hands off.
        for t in ["handoff", "question", "read", "bash"] {
            assert!(names.contains(&t), "Auto missing `{t}`: {names:?}");
        }
        // It owns no write/lock and no code-writing delegation — the
        // swapped-in primary does the work.
        for t in ["readlock", "writeunlock", "editunlock", "unlock", "task"] {
            assert!(!names.contains(&t), "Auto must not hold `{t}`");
        }
    }

    #[test]
    fn load_dispatches_auto() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            load("Auto", &test_spawn_args(tmp.path())).unwrap().name,
            "Auto"
        );
    }

    #[test]
    fn auto_is_noninteractive_default() {
        // `Auto` is a primary, never delegated to via `task`; it isn't in
        // the interactive-handoff set, so it defaults to noninteractive.
        assert!(is_noninteractive("Auto"));
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
    fn grant_composes_onto_explore_for_one_run_only() {
        // Per-delegation tool grants (prompt `parent-granted-tools.md`): a
        // parent granting `mcp` to an `explore` delegation makes
        // the child's effective surface = base + grants, for that run only.
        let tmp = tempfile::tempdir().unwrap();
        let base = test_spawn_args(tmp.path());

        // No MCP in `explore`'s base surface.
        let plain = load("explore", &base).unwrap();
        assert!(!plain.tools.names().contains(&"mcp"));

        // A delegation that grants MCP: the child holds it for this spawn.
        let granted_args = SpawnArgs {
            granted_tools: vec!["mcp".to_string()],
            ..test_spawn_args(tmp.path())
        };
        let granted = load("explore", &granted_args).unwrap();
        assert!(granted.tools.names().contains(&"mcp"));

        // A subsequent delegation WITHOUT the grant has the base surface again
        // — grants don't persist or leak across delegations.
        let after = load("explore", &test_spawn_args(tmp.path())).unwrap();
        assert!(!after.tools.names().contains(&"mcp"));
    }

    #[test]
    fn builtin_prompt_for_resolves_frontier_then_normal_then_defensive() {
        use crate::config::extended::LlmMode;
        // A single-mode agent resolves to the flat defensive body in every
        // mode — the belt-and-suspenders fallback.
        assert_eq!(
            builtin_prompt_for(AUTO_PROMPT, None, None, LlmMode::Normal),
            AUTO_PROMPT
        );
        assert_eq!(
            builtin_prompt_for(AUTO_PROMPT, None, None, LlmMode::Frontier),
            AUTO_PROMPT
        );
        assert_eq!(
            builtin_prompt_for(AUTO_PROMPT, None, None, LlmMode::Defensive),
            AUTO_PROMPT
        );
        // With a normal variant present, Normal selects it, Frontier falls
        // back to it, and Defensive keeps the flat body.
        assert_eq!(
            builtin_prompt_for(AUTO_PROMPT, Some(AUTO_PROMPT_NORMAL), None, LlmMode::Normal),
            AUTO_PROMPT_NORMAL
        );
        assert_eq!(
            builtin_prompt_for(
                AUTO_PROMPT,
                Some(AUTO_PROMPT_NORMAL),
                None,
                LlmMode::Frontier
            ),
            AUTO_PROMPT_NORMAL
        );
        assert_eq!(
            builtin_prompt_for(
                AUTO_PROMPT,
                Some(AUTO_PROMPT_NORMAL),
                None,
                LlmMode::Defensive
            ),
            AUTO_PROMPT
        );
        assert_eq!(
            builtin_prompt_for(
                AUTO_PROMPT,
                Some(AUTO_PROMPT_NORMAL),
                Some("FRONTIER BODY"),
                LlmMode::Frontier
            ),
            "FRONTIER BODY"
        );
    }

    #[test]
    fn learn_is_reachable_from_write_capable_swarm() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args(tmp.path());
        let agent = swarm(&args);
        assert!(agent.tools.names().contains(&"skill_manage"));
    }

    #[test]
    fn delegate_agent_defs_expose_tiered_docs_policy() {
        for (name, body) in [
            ("build", BUILD_PROMPT),
            ("builder", BUILDER_PROMPT),
            ("swarm", SWARM_PROMPT),
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
            ("build.normal", BUILD_PROMPT_NORMAL),
            ("builder.normal", BUILDER_PROMPT_NORMAL),
            ("swarm.normal", SWARM_PROMPT_NORMAL),
            ("bee.normal", BEE_PROMPT_NORMAL),
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
                "`{name}` normal body must steer away from guessing/web-searching uncertain APIs"
            );
        }
        for (name, body) in [
            ("build.frontier", BUILD_PROMPT_FRONTIER),
            ("builder.frontier", BUILDER_PROMPT_FRONTIER),
            ("swarm.frontier", SWARM_PROMPT_FRONTIER),
            ("bee.frontier", BEE_PROMPT_FRONTIER),
        ] {
            let low = body.to_lowercase();
            assert!(low.contains("docs"), "`{name}` must name docs");
            assert!(
                low.contains("unfamiliar") || low.contains("version-specific"),
                "`{name}` frontier body must describe when docs is useful"
            );
            assert!(
                !low.contains("first move"),
                "`{name}` frontier body must not force docs as first move"
            );
        }
    }

    /// Web tools (`webfetch`/`websearch`) note the prefer-`docs`-for-dependency-
    /// API guidance (implementation note): web stays
    /// available for what `docs` can't answer (news, non-package info).
    #[test]
    fn web_tool_defaults_note_prefer_docs_for_dependency_api() {
        for name in ["webfetch", "websearch"] {
            let tpl = crate::tools::custom_templates::default_template_for(name);
            let desc = tpl.description.unwrap_or_default().to_lowercase();
            assert!(
                desc.contains("docs"),
                "`{name}` default description must mention preferring `docs`"
            );
            assert!(
                desc.contains("can't answer") || desc.contains("cannot answer"),
                "`{name}` default description must note web is for what `docs` can't answer"
            );
        }
    }

    /// The per-agent `task` description override (`Build`/`builder`) follows
    /// the same defensive/normal/frontier docs strength as the prompts.
    #[test]
    fn task_override_uses_tiered_docs_policy_by_mode() {
        use crate::config::extended::LlmMode;
        let tmp = tempfile::tempdir().unwrap();
        for mode in [LlmMode::Defensive, LlmMode::Normal, LlmMode::Frontier] {
            let mut args = test_spawn_args(tmp.path());
            args.llm_mode = mode;
            for build_agent in [build(&args), builder(&args)] {
                let defs = build_agent.tools.definitions(mode);
                let task = defs
                    .iter()
                    .find(|d| d.name == "task")
                    .unwrap_or_else(|| panic!("`{}` must hold `task`", build_agent.name));
                let low = task.description.to_lowercase();
                assert!(
                    low.contains("docs"),
                    "`{}` ({mode:?}) `task` desc must name `docs`: {}",
                    build_agent.name,
                    task.description
                );
                match mode {
                    LlmMode::Defensive => assert!(
                        low.contains("first move"),
                        "`{}` defensive `task` desc must make docs the first move: {}",
                        build_agent.name,
                        task.description
                    ),
                    LlmMode::Normal => assert!(
                        low.contains("by default") && low.contains("unfamiliar"),
                        "`{}` normal `task` desc must make docs the default for uncertainty: {}",
                        build_agent.name,
                        task.description
                    ),
                    LlmMode::Frontier => {
                        assert!(
                            low.contains("when") && low.contains("unfamiliar"),
                            "`{}` frontier `task` desc must expose discretionary docs: {}",
                            build_agent.name,
                            task.description
                        );
                        assert!(
                            !low.contains("first move"),
                            "`{}` frontier `task` desc must not force docs first: {}",
                            build_agent.name,
                            task.description
                        );
                    }
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
        for (name, prompt) in [
            ("explore", EXPLORE_PROMPT),
            ("explore.normal", EXPLORE_PROMPT_NORMAL),
        ] {
            for tool in [
                "context_pack",
                "tree",
                "symbol_find",
                "search",
                "impact",
                "bash",
            ] {
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
    fn explore_gets_seed_tool_in_normal_mode_only() {
        let tmp = tempfile::tempdir().unwrap();
        // Defensive (default): the feature is gated off — no `seed` tool.
        let mut args = test_spawn_args(tmp.path());
        args.llm_mode = crate::config::extended::LlmMode::Defensive;
        assert!(!explore(&args).tools.names().contains(&"seed"));
        // Normal: the capability is enabled, so the read-only noninteractive
        // subagent carries `seed`.
        args.llm_mode = crate::config::extended::LlmMode::Normal;
        assert!(explore(&args).tools.names().contains(&"seed"));
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
    fn delegated_builder_advertises_only_allowed_recursive_targets() {
        let tmp = tempfile::tempdir().unwrap();
        let mut args = test_spawn_args(tmp.path());
        args.delegated = true;
        args.delegation_recursion = DelegationRecursionContext {
            enabled: true,
            remaining_depth: 1,
            allowed_targets: vec!["docs".to_string()],
            same_model_only: false,
        };

        let agent = builder(&args);
        let task = task_definition(&agent, crate::config::extended::LlmMode::Normal);
        let agent_enum = task.parameters["properties"]["payload"]["properties"]["agent"]["enum"]
            .as_array()
            .expect("agent enum");
        assert_eq!(agent_enum, &vec![serde_json::json!("docs")]);
    }

    #[test]
    fn delegated_tool_using_subagent_can_advertise_deepthink_when_enabled_and_allowed() {
        let tmp = tempfile::tempdir().unwrap();
        write_project_config(tmp.path(), r#"{"deepthink":{"enabled":true}}"#);
        let mut args = test_spawn_args(tmp.path());
        args.delegated = true;
        args.delegation_recursion = DelegationRecursionContext {
            enabled: true,
            remaining_depth: 1,
            allowed_targets: vec!["deepthink".to_string()],
            same_model_only: false,
        };

        let agent = builder(&args);
        let task = task_definition(&agent, crate::config::extended::LlmMode::Normal);
        let agent_enum = task.parameters["properties"]["payload"]["properties"]["agent"]["enum"]
            .as_array()
            .expect("agent enum");
        assert_eq!(agent_enum, &vec![serde_json::json!("deepthink")]);
    }

    #[test]
    fn delegated_explore_recursion_is_same_model_explore_only() {
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
        let task = task_definition(&agent, crate::config::extended::LlmMode::Normal);
        assert!(
            task.description.contains("same resolved model"),
            "{}",
            task.description
        );
        let agent_enum = task.parameters["properties"]["payload"]["properties"]["agent"]["enum"]
            .as_array()
            .expect("agent enum");
        assert_eq!(agent_enum, &vec![serde_json::json!("explore")]);
    }

    #[test]
    fn build_task_description_is_per_agent_overridden_and_composes_with_mode() {
        // `Build` registers a per-agent override on `task` (delegate-eager
        // intent, prompt `per-agent-tool-definitions.md`). The override wins
        // over the tool's own description in normal/defensive modes, composes
        // with the per-mode axis, and leaves the SCHEMA untouched — same tool
        // ID + parameters as the base `task` tool. Frontier has no authored
        // override here, so it falls back to the base terse description.
        let tmp = tempfile::tempdir().unwrap();
        let mut normal_args = test_spawn_args(tmp.path());
        normal_args.llm_mode = crate::config::extended::LlmMode::Normal;
        let mut defensive_args = test_spawn_args(tmp.path());
        defensive_args.llm_mode = crate::config::extended::LlmMode::Defensive;
        let mut frontier_args = test_spawn_args(tmp.path());
        frontier_args.llm_mode = crate::config::extended::LlmMode::Frontier;

        let build_normal = build(&normal_args);
        let build_defensive = build(&defensive_args);
        let build_frontier = build(&frontier_args);

        let task_normal = build_normal
            .tools
            .definitions(crate::config::extended::LlmMode::Normal)
            .into_iter()
            .find(|d| d.name == "task")
            .expect("Build holds task");
        let task_defensive = build_defensive
            .tools
            .definitions(crate::config::extended::LlmMode::Defensive)
            .into_iter()
            .find(|d| d.name == "task")
            .expect("Build holds task");
        let task_frontier = build_frontier
            .tools
            .definitions(crate::config::extended::LlmMode::Frontier)
            .into_iter()
            .find(|d| d.name == "task")
            .expect("Build holds task");

        // The override text is present (delegate-eager intent), not the tool's
        // own base description.
        assert!(
            task_normal.description.contains("substantive feature work"),
            "Build normal `task` must carry the per-agent intent: {}",
            task_normal.description
        );
        // Normal and defensive select different text — per-mode axis preserved
        // on top of the per-agent override.
        assert_ne!(task_normal.description, task_defensive.description);

        // SCHEMA is identical to the un-overridden `task` tool: same ID + same
        // parameters. The override never touched the schema.
        let base = crate::tools::task::TaskTool::with_subagents(
            &build_subagents(tmp.path())
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );
        let base_def = crate::engine::tool::definition_of(
            &base,
            crate::config::extended::LlmMode::Normal,
            None,
        );
        let base_frontier = crate::engine::tool::definition_of(
            &base,
            crate::config::extended::LlmMode::Frontier,
            None,
        );
        assert_eq!(task_normal.name, base_def.name);
        assert_eq!(task_normal.parameters, base_def.parameters);
        // …and the description genuinely differs from the un-overridden one.
        assert_ne!(task_normal.description, base_def.description);
        assert_eq!(task_frontier.name, base_frontier.name);
        assert_eq!(task_frontier.parameters, base_frontier.parameters);
        assert_ne!(task_frontier.description, base_frontier.description);
        assert!(
            task_frontier
                .description
                .contains("Write small local edits directly"),
            "{}",
            task_frontier.description
        );
    }

    fn task_definition(
        agent: &Agent,
        mode: crate::config::extended::LlmMode,
    ) -> crate::engine::message::ToolDefinition {
        agent
            .tools
            .definitions(mode)
            .into_iter()
            .find(|d| d.name == "task")
            .expect("agent holds task")
    }

    #[test]
    fn defensive_build_prompt_and_task_description_preserve_delegation_steer() {
        let tmp = tempfile::tempdir().unwrap();
        let mut args = test_spawn_args(tmp.path());
        args.llm_mode = crate::config::extended::LlmMode::Defensive;

        let agent = build(&args);
        let task = task_definition(&agent, crate::config::extended::LlmMode::Defensive);

        for needle in [
            "Substantive implementation goes to `{\"intent\":\"delegate\",\"payload\":{\"agent\":\"builder\",\"prompt\":\"...\"}}`",
            "FIRST move is `{\"intent\":\"delegate\",\"payload\":{\"agent\":\"docs\"",
            "dependency API questions discovered while preparing a `builder` brief",
            "one `builder` task is one implementation slice",
            "delegate again to a fresh `builder` brief seeded with the prior result summary",
            "Task background contract:",
            "Do not treat that as the report and do not redelegate the same work solely because it backgrounded",
            "Read each child `status` (`completed`, `failed`, `cancelled`, `lost`) and optional `error`",
        ] {
            assert!(
                agent.role_prompt.contains(needle),
                "Build defensive prompt missing `{needle}`:\n{}",
                agent.role_prompt
            );
        }

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
                "Build defensive task description missing `{needle}`:\n{}",
                task.description
            );
        }
    }

    #[test]
    fn defensive_builder_prompt_and_task_description_preserve_scope_steer() {
        let tmp = tempfile::tempdir().unwrap();
        let mut args = test_spawn_args(tmp.path());
        args.llm_mode = crate::config::extended::LlmMode::Defensive;

        let agent = builder(&args);
        let task = task_definition(&agent, crate::config::extended::LlmMode::Defensive);

        for needle in [
            "Do exactly one assigned implementation slice yourself",
            "return that out-of-scope ask to your caller through the structured `return` report",
            "FIRST move is to delegate to the `docs` subagent",
            "If the `docs` task backgrounds",
            "read per-child `status`/`error` because docs can fail",
            "exact usage pattern is clearly established in already-read local code",
            "Do not use `task` to delegate the feature itself",
        ] {
            assert!(
                agent.role_prompt.contains(needle),
                "builder defensive prompt missing `{needle}`:\n{}",
                agent.role_prompt
            );
        }

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
                "builder defensive task description missing `{needle}`:\n{}",
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
        assert_eq!(enum_values, vec!["docs"]);
    }

    #[test]
    fn frontier_build_prompt_permits_direct_small_edits_with_lock_tools() {
        let tmp = tempfile::tempdir().unwrap();
        let mut frontier = test_spawn_args(tmp.path());
        frontier.llm_mode = crate::config::extended::LlmMode::Frontier;
        let mut defensive = test_spawn_args(tmp.path());
        defensive.llm_mode = crate::config::extended::LlmMode::Defensive;

        let frontier_agent = build(&frontier);
        let defensive_agent = build(&defensive);
        let frontier_task =
            task_definition(&frontier_agent, crate::config::extended::LlmMode::Frontier);

        for needle in [
            "may directly make small local edits",
            "`readlock(path, offset?, limit?)`",
            "`writeunlock(path, content)`",
            "`editunlock(path, old_string, new_string, replace_all?)`",
            "`unlock(path)`",
            "Delegate when the change needs broad search",
            "run the relevant build/test/check command",
        ] {
            assert!(
                frontier_agent.role_prompt.contains(needle),
                "frontier Build prompt missing `{needle}`:\n{}",
                frontier_agent.role_prompt
            );
        }
        assert!(
            frontier_task
                .description
                .contains("Write small local edits directly"),
            "{}",
            frontier_task.description
        );
        assert!(
            frontier_task
                .description
                .contains("delegate larger, multi-file, risky, or isolated work"),
            "{}",
            frontier_task.description
        );

        assert!(
            defensive_agent.role_prompt.contains("You are not a writer"),
            "{}",
            defensive_agent.role_prompt
        );
        assert!(
            !defensive_agent
                .role_prompt
                .contains("may directly make small local edits"),
            "{}",
            defensive_agent.role_prompt
        );
    }

    #[test]
    fn normal_build_and_builder_task_descriptions_stay_terse() {
        let tmp = tempfile::tempdir().unwrap();
        let mut args = test_spawn_args(tmp.path());
        args.llm_mode = crate::config::extended::LlmMode::Normal;

        let build_task = task_definition(&build(&args), crate::config::extended::LlmMode::Normal);
        let builder_task =
            task_definition(&builder(&args), crate::config::extended::LlmMode::Normal);

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
            "normal Build task description grew too verbose: {}",
            build_task.description
        );
        assert!(
            builder_task.description.len() < 320,
            "normal builder task description grew too verbose: {}",
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
            ToolDescriptionSpec::Both("builder: read the file you will edit yourself".to_string()),
        );
        let def = AgentDef {
            name: "builder".to_string(),
            description: "do-it-yourself".to_string(),
            mode: AgentMode::Primary,
            model: None,
            temperature: None,
            tools: Some(vec!["read".to_string(), "bash".to_string()]),
            tool_descriptions,
            scan_tool_results: Some(true),
            permission: None,
            prompt: "body".to_string(),
            prompt_variants: std::collections::HashMap::new(),
            source: std::path::PathBuf::from("builder.md"),
        };
        let agent = agent_from_def(&def, &args).unwrap();
        let read_def = agent
            .tools
            .definitions(crate::config::extended::LlmMode::Normal)
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
            .definitions(crate::config::extended::LlmMode::Normal)
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
            tool_descriptions: std::collections::BTreeMap::new(),
            scan_tool_results: Some(true),
            permission: None,
            prompt: "body".to_string(),
            prompt_variants: std::collections::HashMap::new(),
            source: tmp.path().join("custom-reader.md"),
        };

        let agent = agent_from_def(&def, &args).unwrap();
        let names = agent.tools.names();
        assert!(names.contains(&"read"));
        assert!(names.contains(&"search"));
        assert!(names.contains(&"websearch"));
        assert!(names.contains(&"webfetch"));
    }

    #[test]
    fn swarm_factory_has_build_surface_plus_recursive_spawn() {
        // `Swarm` (GOALS §24) mirrors `Build`'s surface and adds the
        // recursive `spawn` fan-out tool — the sole leaf-termination
        // exception. It can delegate to `builder` (writes flow through the
        // single writer) and to itself via `spawn`.
        let tmp = tempfile::tempdir().unwrap();
        let agent = swarm(&test_spawn_args(tmp.path()));
        assert_eq!(agent.name, "Swarm");
        let names = agent.tools.names();
        // Build's surface.
        for t in ["read", "bash", "tree", "hot", "schedule", "task", "skill"] {
            assert!(names.contains(&t), "Swarm missing `{t}`: {names:?}");
        }
        // The recursive fan-out tool.
        assert!(
            names.contains(&"spawn"),
            "Swarm must hold `spawn`: {names:?}"
        );
    }

    #[test]
    fn can_delegate_false_hides_delegation_tools() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args_with_provider_can_delegate(tmp.path(), Some(false));
        let agent = swarm(&args);
        let session = crate::session::Session::create(
            crate::db::Db::open_in_memory().unwrap(),
            tmp.path().to_path_buf(),
            "Swarm",
        )
        .unwrap();

        let toolbox = crate::engine::agent::turn_toolbox(&agent, &session, tmp.path());
        let names = toolbox.names();

        assert!(!names.contains(&"task"), "{names:?}");
        assert!(!names.contains(&"spawn"), "{names:?}");
    }

    #[test]
    fn can_delegate_unset_keeps_delegation_tools() {
        let tmp = tempfile::tempdir().unwrap();
        let args = test_spawn_args_with_provider_can_delegate(tmp.path(), None);
        let agent = swarm(&args);
        let session = crate::session::Session::create(
            crate::db::Db::open_in_memory().unwrap(),
            tmp.path().to_path_buf(),
            "Swarm",
        )
        .unwrap();

        let toolbox = crate::engine::agent::turn_toolbox(&agent, &session, tmp.path());
        let names = toolbox.names();

        assert!(names.contains(&"task"), "{names:?}");
        assert!(names.contains(&"spawn"), "{names:?}");
    }

    #[test]
    fn can_delegate_gates_subagent_turns() {
        // Subagent and primary turns share `turn_toolbox`; proving the filter
        // there covers every spawned child before the model sees its tools.
        let tmp = tempfile::tempdir().unwrap();
        let mut args = test_spawn_args_with_provider_can_delegate(tmp.path(), Some(false));
        args.delegated = true;
        let agent = bee(&args);
        let session = crate::session::Session::create(
            crate::db::Db::open_in_memory().unwrap(),
            tmp.path().to_path_buf(),
            "bee",
        )
        .unwrap();

        let toolbox = crate::engine::agent::turn_toolbox(&agent, &session, tmp.path());
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
            "read",
            "bash",
            "readlock",
            "writeunlock",
            "editunlock",
            "unlock",
            "tree",
            "search",
            "skill",
            "task",
            "spawn",
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
            .definitions(crate::config::extended::LlmMode::Defensive)
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
    fn swarm_task_targets_exclude_primaries_recursion_is_spawn_only() {
        // Swarm→Swarm is the ONLY new edge, and it goes through
        // `spawn`, not `task`. The `task` enum must still offer only
        // the normal subagents (builder/explore/docs) — never `Plan`/`Build`/
        // `Swarm` — so leaf-termination otherwise holds (GOALS §24).
        let tmp = tempfile::tempdir().unwrap();
        let agent = swarm(&test_spawn_args(tmp.path()));
        let def = agent
            .tools
            .definitions(crate::config::extended::LlmMode::Defensive)
            .into_iter()
            .find(|d| d.name == "task")
            .expect("task tool present");
        let enum_vals = def.parameters["properties"]["payload"]["properties"]["agent"]["enum"]
            .as_array()
            .expect("agent enum present");
        let names: Vec<&str> = enum_vals.iter().filter_map(|v| v.as_str()).collect();
        assert!(names.contains(&"builder"), "{names:?}");
        assert!(names.contains(&"explore"), "{names:?}");
        for forbidden in ["Plan", "Build", "Swarm", "Auto"] {
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
        // the caller to give each child a dedicated output folder/DB (the
        // primary contention-avoidance mechanism, GOALS §24 / §10).
        let tmp = tempfile::tempdir().unwrap();
        let mut args = test_spawn_args(tmp.path());
        args.swarm_depth = 1;
        args.swarm_max_depth = 4;
        let agent = swarm(&args);
        let def = agent
            .tools
            .definitions(args.llm_mode)
            .into_iter()
            .find(|d| d.name == "spawn")
            .expect("spawn tool present");
        let desc = &def.description;
        assert!(desc.contains("depth 1"), "depth in description: {desc}");
        assert!(desc.contains("ceiling 4"), "ceiling in description: {desc}");
        assert!(
            desc.contains("output_dir") && desc.contains("dedicated"),
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
            tool_descriptions: std::collections::BTreeMap::new(),
            scan_tool_results: None,
            permission: None,
            prompt: "body".to_string(),
            prompt_variants: std::collections::HashMap::new(),
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
