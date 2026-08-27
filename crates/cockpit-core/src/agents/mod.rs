//! Agent definition discovery, parsing, resolution, and invariant
//! validation.
//!
//! On-disk format: YAML frontmatter + Markdown body. The frontmatter shape
//! is inspired by opencode's agent files (we own the file layout but
//! the field names track theirs where the design is good — see
//! `the CLI design notes` §4 for the schema).
//!
//! ```text
//! ---
//! description: One-line description.
//! mode: subagent
//! model: anthropic/claude-opus-4-7
//! temperature: 0.2
//! tools: [read, bash, search]
//! ---
//! <markdown body == the agent's system prompt>
//! ```
//!
//! Disk model (implementation note): the bundled cast
//! (`Build`, `builder`, `explore`) stays **embedded** in the binary as
//! fallback [`AgentDef`]s. Nothing is written on first run. "Editing" a
//! built-in *ejects* its default to `.cockpit/agents/<name>.md`; from then
//! on the on-disk file overrides the embedded default **by name**.
//! "Reset" deletes the override. Custom agents (any non-built-in name)
//! live only on disk and are never touched by reset.
//!
//! Single-file defs (`agents/<name>.md`) remain fully valid. A directory
//! package (`agents/<name>/agent.md` plus optional `subagents/`, `mcp.json`,
//! and per-slot prompt overrides) is opt-in. Resolution is nearest-project-
//! wins: a workspace def is not silently shadowed by a home def.
//!
//! The docs two-stage pipeline (Docs.1 / Docs.2) is **not** an [`AgentDef`]
//! — it stays entirely hardcoded in [`crate::engine::builtin`] and
//! [`crate::engine::docs_pipeline`] and is never exposed here.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

mod builtin_defs;
pub(crate) mod invariants;
mod profile;
mod vnext;

pub(crate) use builtin_defs::embedded_internal_default;
pub use builtin_defs::{
    BUILTIN_AGENT_NAMES, FALLBACK_PRIMARY, embedded_default, is_builtin_agent, is_builtin_primary,
    is_hidden_primary, is_removed_primary, resolve_primary,
};
pub use invariants::validate_invariants;
pub use profile::{
    AgentProfileDefinition, AgentProfileFallbackRoute, AgentProfileInstallationCatalog,
    AgentProfileInstallationSource, AgentProfileModelOffering, AgentProfilePrepareRequest,
    AgentProfileResolutionInput, ProfileQuestionOverride, ProfileVerificationReduction,
    ReloadedAgentProfile, ResolvedAgentProfile, ResolvedModelSlot, ResolvedModelSlotChoice,
    ranked_compatible_offerings, resolve_agent_profile,
};
pub(crate) use profile::{
    prepared_route_is_compatible, redacted_child_route_is_compatible, redacted_slot_requirements,
};
pub(crate) use vnext::DefinitionScope;
pub(crate) use vnext::author_slot;
pub use vnext::{
    AllowedChild, AutoAnswer, CompiledVerificationPolicy, CompiledVerificationRegion,
    DelegationPolicy, DelegationTarget, EffectiveDelegationGrant, EffectiveQuestionPolicy,
    EffectiveVnextGrant, ExecutionKind, GeneratorSpec, LocalInstallationIdentity,
    LocalInstallationResolver, MAX_GENERATOR_TURNS, MAX_VERIFICATION_CANDIDATES, ModelCapability,
    ModelLocality, ModelRecommendation, ModelSlot, OnAdjudicationFailure, OnBudgetExceeded,
    PROFILE_CLEAN_ROOM, PROFILE_PANEL, PROFILE_SELF_CHECK, PreparedPrimarySlotRoute,
    ProhibitedQuestionClass, ProviderAlias, QuestionOverride, QuestionPolicy, ResolverOrder,
    SCHEMA_VERSION, SELF_CHILD_REF, SelectorPredicate, SlotModelRef, ToolClass, VerificationAction,
    VerificationBudget, VerificationDispatch, VerificationEstimate, VerificationMode,
    VerificationPolicy, VerificationRecipe, VerificationRule, VerificationSelector,
    VerificationSessionReduction, VerificationSubject, VnextAgentDef, VnextHostPolicy,
    delegation_kind_permitted, resolve_question_policy,
};

const MAX_MARKDOWN_BYTES: u64 = 1024 * 1024;
/// Whole-tree cap for an agent definition package (`agents/<name>/`).
const MAX_PACKAGE_BYTES: u64 = 4 * 1024 * 1024;
pub(crate) const MAX_PACKAGE_ENTRIES: usize =
    cockpit_host::private_fs::MAX_NOFOLLOW_DIRECTORY_TREE_ENTRIES;
pub(crate) const MAX_PACKAGE_DEPTH: usize =
    cockpit_host::private_fs::MAX_NOFOLLOW_DIRECTORY_TREE_DEPTH;
pub(crate) const PACKAGE_ROOT_FILE: &str = "agent.md";
pub(crate) const PACKAGE_SUBAGENTS_DIR: &str = "subagents";
const PACKAGE_MCP_FILE: &str = "mcp.json";

/// Per-agent capability grants (issue #75). These replace the four
/// mode-gated [`crate::engine::tool::Capability`] variants: a grant is now
/// an explicit member of the agent definition's `capabilities` set rather
/// than a side effect of a session-global steering posture. Wire names are the
/// camelCase spellings below.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AgentCapability {
    FollowupSeed,
    SandboxEscalate,
    ForkContext,
    ScopedParallelWrite,
}

impl AgentCapability {
    pub fn from_wire(name: &str) -> Option<Self> {
        match name {
            "followupSeed" => Some(Self::FollowupSeed),
            "sandboxEscalate" => Some(Self::SandboxEscalate),
            "forkContext" => Some(Self::ForkContext),
            "scopedParallelWrite" => Some(Self::ScopedParallelWrite),
            _ => None,
        }
    }

    pub fn wire_name(self) -> &'static str {
        match self {
            Self::FollowupSeed => "followupSeed",
            Self::SandboxEscalate => "sandboxEscalate",
            Self::ForkContext => "forkContext",
            Self::ScopedParallelWrite => "scopedParallelWrite",
        }
    }
}

/// Per-agent tool-description steering (issue #75). `Verbose` renders the
/// former `verbose_description()`/`verbose_parameters()` text; `Terse`
/// renders the normal/base text. Defaults to `Terse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolSteering {
    #[default]
    Terse,
    Verbose,
}

impl ToolSteering {
    /// Resolve the steering from an agent definition: the declared
    /// `toolSteering` wins, otherwise the default `Terse` (issue #75
    /// closure — no code path derives steering from a session-global mode).
    pub fn from_def(def: &AgentDef) -> Self {
        def.tool_steering.unwrap_or_default()
    }
}

/// Inline-caps profile for context tagging (issue #75). Replaces
/// `TagInlineCaps::for_mode`. Defaults to `Standard` (48 KiB).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InlineCapsProfile {
    Conservative,
    #[default]
    Standard,
    Large,
}

/// Per-agent context policy (issue #75). Replaces the mode-derived
/// auto-compact floor and inline-caps profile. Defaults:
/// `auto_compact_pct = 80`, `inline_caps = Standard`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ContextPolicy {
    #[serde(
        rename = "autoCompactPct",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub auto_compact_pct: Option<u8>,
    #[serde(
        rename = "inlineCaps",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub inline_caps: Option<InlineCapsProfile>,
}

impl ContextPolicy {
    /// The default auto-compact percentage (80) used when the def does not
    /// declare one.
    pub const DEFAULT_AUTO_COMPACT_PCT: u8 = 80;
}

/// The resolved posture of one agent node (issue #75): the single value the
/// engine consults for capability grants. It carries
/// the resolved capability-grant set. When the [`AgentDef`] declares
/// `capabilities`, that set is authoritative; when it does not (`None`), the
/// `standard` fallback grant set (empty — none of the four capabilities)
/// applies.
///
/// The only constructor is [`PostureResolution::from_def`], which lives in
/// this module: no engine site can synthesize a grant set (closure ratchet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureResolution {
    grants: BTreeSet<AgentCapability>,
}

impl PostureResolution {
    /// Resolve posture from an agent definition. When `def.capabilities` is
    /// `Some`, the declared set is authoritative; when `None`, the `standard`
    /// fallback (no capabilities) applies.
    pub fn from_def(def: &AgentDef) -> Self {
        Self {
            grants: def.capabilities.clone().unwrap_or_default(),
        }
    }

    /// The `standard` fallback posture: no capability grants (issue #75,
    /// decision 6). Used for cold start and delegation to an undescribed
    /// model.
    pub fn standard() -> Self {
        Self {
            grants: BTreeSet::new(),
        }
    }

    /// Construct a posture from an explicit grant set. This is the derivation
    /// seam for a model-override def (the governing def's grants, slot
    /// substituted) and the test fixture seam. Production resolution paths
    /// use [`Self::from_def`].
    pub(crate) fn from_grants(grants: BTreeSet<AgentCapability>) -> Self {
        Self { grants }
    }

    /// The resolved grant set.
    pub fn grants(&self) -> &BTreeSet<AgentCapability> {
        &self.grants
    }

    /// Apply the no-widening delegation rule: a child may retain only grants
    /// that are also present on its direct parent.
    pub fn intersect_parent(&self, parent: &Self) -> Self {
        Self {
            grants: self.grants.intersection(&parent.grants).copied().collect(),
        }
    }

    /// Whether a given [`crate::engine::tool::Capability`] is enabled under
    /// this posture: membership in the resolved grant set decides.
    pub fn capability_enabled(&self, cap: crate::engine::tool::Capability) -> bool {
        self.grants.contains(&cap.into())
    }
}

/// A fully-resolved agent definition: the embedded default for a
/// built-in, or a user-authored file on disk. The `model`/`temperature`/
/// `tools` here are what the engine builds the agent from — an edited
/// override therefore takes effect on the next agent run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDef {
    /// The agent's name. Not part of the frontmatter — it is the file
    /// stem (`<name>.md` or the `<name>/` directory). Carried here for
    /// dispatch and override-by-name resolution.
    #[serde(skip)]
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub mode: AgentMode,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub temperature: Option<f32>,
    #[serde(default)]
    pub tools: Option<Vec<String>>,
    /// Per-agent tool placement. Omitted tools use the role default; for
    /// user-authored definitions without a role default, omission means
    /// [`ToolTier::Enabled`].
    #[serde(rename = "toolTiers", default)]
    pub tool_tiers: BTreeMap<String, ToolTier>,
    /// Per-agent tool-description overrides (prompt
    /// `per-agent-tool-definitions.md`): re-word a granted tool's *description*
    /// for **this** agent without touching its ID or schema, so the same tool
    /// can encode different per-agent intent (e.g. `Build` "delegate-eager" vs
    /// a "do-it-yourself" primary). Keyed by tool name; the value carries the
    /// terse/verbose steering text. Applied at
    /// [`crate::engine::builtin`] construction time onto the toolbox via
    /// [`crate::engine::tool::ToolBox::with_override`] — fixed at session
    /// start, so the tools array stays byte-stable (cache-safe). Empty / absent
    /// means every tool keeps its base description (byte-identical to today).
    #[serde(default, deserialize_with = "deserialize_tool_descriptions")]
    pub tool_descriptions: BTreeMap<String, ToolDescriptionSpec>,
    /// Whether this agent's untrusted tool/subagent results are scanned by the
    /// prompt-injection guard before entering parent history. `None` means use
    /// the role/name default.
    #[serde(rename = "scanToolResults", default)]
    pub scan_tool_results: Option<bool>,
    /// Per-agent goal verification overrides. Empty fields inherit from the
    /// session override (when present) and then global `ExtendedConfig`.
    #[serde(
        rename = "goalSupervision",
        default,
        skip_serializing_if = "GoalSettingsOverride::is_empty"
    )]
    pub goal_supervision: GoalSettingsOverride,
    #[serde(default)]
    pub permission: Option<serde_json::Value>,
    /// Explicit per-agent capability grants (issue #75). `None` = "not
    /// declared" (resolves to the `standard` fallback grant set — none of
    /// the four capabilities); `Some(empty)` = explicitly none. The four
    /// variants mirror the [`crate::engine::tool::Capability`] set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<BTreeSet<AgentCapability>>,
    /// Per-agent tool-description steering (issue #75). `None` = not declared
    /// (default `Terse`); `Some` selects the rendering directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_steering: Option<ToolSteering>,
    /// Per-agent context policy (issue #75): the auto-compact floor and inline
    /// caps profile. `None` = not declared (inherit the default 80 /
    /// `standard`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_policy: Option<ContextPolicy>,
    /// Parsed v2 declarative contract.  v2 never projects into the legacy
    /// runtime fields: a host must calculate and snapshot an
    /// [`EffectiveVnextGrant`] before a v2 definition can receive any
    /// capability at all.
    #[serde(skip)]
    pub vnext: Option<VnextAgentDef>,
    /// Body of the markdown file (the agent's system prompt). This is *the*
    /// single canonical body for the agent (issue #75: the old per-posture
    /// body trios are merged into one). Per-model override bodies live in
    /// [`Self::prompt_overrides`]. Resolved through
    /// [`AgentDef::resolved_prompt`] rather than read directly so the
    /// per-model override threads through one path.
    #[serde(skip)]
    pub prompt: String,
    /// Per-model prompt-body overrides for a directory-form agent
    /// (`<dir>/<name>/<key>.md`, keyed by model-slot name or model id). Empty
    /// for a flat-file or embedded agent. When present,
    /// [`AgentDef::resolved_prompt`] selects the override matching the
    /// `model_hint`, falling back to [`Self::prompt`] (the canonical body)
    /// when no override matches.
    #[serde(skip)]
    pub prompt_overrides: BTreeMap<String, String>,
    /// Whole-tree package files (`relative/posix/path` → bytes) when this
    /// definition was loaded from `agents/<name>/`. `None` for a single-file
    /// def so [`AgentDef::vnext_digest_bytes`] stays byte-identical to the
    /// pre-package `to_markdown()` preimage.
    #[serde(skip)]
    pub package_files: Option<BTreeMap<String, Vec<u8>>>,
    /// Private subagent definitions loaded from `subagents/<child>.md`.
    /// Resolvable only through this parent's `allowed_children` (Stage 3).
    #[serde(skip)]
    pub private_subagents: BTreeMap<String, AgentDef>,
    /// Path the definition was loaded from (`<dir>/<name>.md` or the
    /// `<dir>/<name>/` directory), or empty for an embedded default. Used
    /// for diagnostics and override detection.
    #[serde(skip)]
    pub source: PathBuf,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ToolTier {
    Enabled,
    Discoverable,
    Disabled,
}

impl ToolTier {
    pub fn label(self) -> &'static str {
        match self {
            ToolTier::Enabled => "enabled",
            ToolTier::Discoverable => "discoverable",
            ToolTier::Disabled => "disabled",
        }
    }

    pub fn from_label(value: &str) -> Option<Self> {
        match value {
            "enabled" => Some(ToolTier::Enabled),
            "discoverable" => Some(ToolTier::Discoverable),
            "disabled" => Some(ToolTier::Disabled),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ToolSurfaceSelection {
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(rename = "toolTiers", default)]
    pub tool_tiers: BTreeMap<String, ToolTier>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolSurfaceItem {
    pub name: &'static str,
    pub family: &'static str,
    pub tiers: &'static [ToolTier],
}

const ALL_TOOL_TIERS: &[ToolTier] = &[
    ToolTier::Enabled,
    ToolTier::Discoverable,
    ToolTier::Disabled,
];
const SAFETY_TOOL_TIERS: &[ToolTier] = &[ToolTier::Enabled];

pub fn known_tool_names() -> &'static [&'static str] {
    invariants::known_tool_names()
}

pub fn legal_tool_tiers(tool: &str) -> &'static [ToolTier] {
    if is_safety_tool(tool) {
        SAFETY_TOOL_TIERS
    } else {
        ALL_TOOL_TIERS
    }
}

pub fn is_safety_tool(tool: &str) -> bool {
    invariants::STRUCTURAL_TOOLS.contains(&tool) || invariants::LOCK_WRITE_TOOLS.contains(&tool)
}

pub fn tool_surface_catalog() -> Vec<ToolSurfaceItem> {
    known_tool_names()
        .iter()
        .map(|name| ToolSurfaceItem {
            name,
            family: tool_family(name),
            tiers: legal_tool_tiers(name),
        })
        .collect()
}

pub fn apply_tool_surface_override(
    def: &mut AgentDef,
    selection: &ToolSurfaceSelection,
) -> Result<()> {
    // Host-owned session overrides remain valid for schemaVersion 2: v2 markdown
    // may not declare `tools:`, but the daemon/TUI still projects a concrete
    // runtime grant onto the in-memory definition before construction.
    let mut candidate = def.clone();
    candidate.tools = Some(selection.tools.clone());
    candidate.tool_tiers = selection.tool_tiers.clone();
    if def.vnext.is_some() {
        validate_host_tool_surface(&candidate)?;
    } else {
        validate_invariants(&candidate)?;
    }
    def.tools = candidate.tools;
    def.tool_tiers = candidate.tool_tiers;
    Ok(())
}

/// Validate a host-projected tool grant on a v2 definition. v2
/// [`validate_invariants`] only checks the closed declarative schema and skips
/// legacy `tools:` rules, so the host override path applies those grant checks
/// explicitly against the projected surface.
fn validate_host_tool_surface(def: &AgentDef) -> Result<()> {
    let Some(vnext) = &def.vnext else {
        return validate_invariants(def);
    };
    vnext.validate()?;
    let Some(tools) = &def.tools else {
        return Ok(());
    };
    // Reuse the same name/role checks a legacy `tools:` grant would see. Keep
    // the definition's existing mode (builtins still carry Primary/Subagent);
    // workspace v2 documents default to `All`.
    let mut legacy = def.clone();
    legacy.vnext = None;
    legacy.tools = Some(tools.clone());
    validate_invariants(&legacy)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GoalSettingsOverride {
    #[serde(
        rename = "defaultTokenBudget",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub default_token_budget: Option<i64>,
    #[serde(
        rename = "plannerModel",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub planner_model: Option<String>,
    #[serde(
        rename = "evaluatorModel",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub evaluator_model: Option<String>,
    #[serde(
        rename = "gatekeeperModel",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub gatekeeper_model: Option<String>,
    #[serde(
        rename = "coldSkepticCount",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cold_skeptic_count: Option<usize>,
    #[serde(
        rename = "coldSkepticModel",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cold_skeptic_model: Option<String>,
    #[serde(
        rename = "maxVerificationAttempts",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_verification_attempts: Option<u32>,
    /// Forward-compatible keys that this daemon does not interpret. Agent
    /// settings mutations preserve them byte-semantically instead of
    /// rebuilding the object from only the three fields exposed by the TUI.
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl GoalSettingsOverride {
    pub fn is_empty(&self) -> bool {
        self.default_token_budget.is_none()
            && self.planner_model.is_none()
            && self.evaluator_model.is_none()
            && self.gatekeeper_model.is_none()
            && self.cold_skeptic_count.is_none()
            && self.cold_skeptic_model.is_none()
            && self.max_verification_attempts.is_none()
            && self.extra.is_empty()
    }

    pub fn validate(&self) -> Result<()> {
        if self.default_token_budget.is_some_and(|budget| budget <= 0) {
            bail!("goalSupervision.defaultTokenBudget must be positive");
        }
        if self
            .cold_skeptic_count
            .is_some_and(|count| !(1..=5).contains(&count))
        {
            bail!("goalSupervision.coldSkepticCount must be between 1 and 5");
        }
        if self.max_verification_attempts == Some(0) {
            bail!("goalSupervision.maxVerificationAttempts must be at least 1");
        }
        for model in [
            self.planner_model.as_deref(),
            self.evaluator_model.as_deref(),
            self.gatekeeper_model.as_deref(),
            self.cold_skeptic_model.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            let trimmed = model.trim();
            if trimmed.is_empty()
                || crate::config::provider::split_provider_model(trimmed).is_none()
            {
                bail!(
                    "goalSupervision model selectors must use provider/model form with non-empty provider and model"
                );
            }
        }
        Ok(())
    }
}

pub fn resolve_goal_supervision_config(
    session: Option<&GoalSettingsOverride>,
    agent: Option<&GoalSettingsOverride>,
    global: crate::config::extended::GoalSupervisionConfig,
) -> crate::config::extended::GoalSupervisionConfig {
    let mut resolved = global;
    if let Some(agent) = agent {
        apply_goal_settings_override(&mut resolved, agent);
    }
    if let Some(session) = session {
        apply_goal_settings_override(&mut resolved, session);
    }
    resolved
}

pub fn effective_goal_supervision_for_agent(
    cwd: &Path,
    agent_name: &str,
    session: Option<&GoalSettingsOverride>,
    global: crate::config::extended::GoalSupervisionConfig,
) -> crate::config::extended::GoalSupervisionConfig {
    let agent_override = resolve(cwd, agent_name)
        .ok()
        .flatten()
        .map(|def| def.goal_supervision);
    resolve_goal_supervision_config(session, agent_override.as_ref(), global)
}

pub fn parse_goal_settings_override_json(raw: &str) -> Result<GoalSettingsOverride> {
    let override_: GoalSettingsOverride = serde_json::from_str(raw)?;
    override_.validate()?;
    Ok(override_)
}

fn apply_goal_settings_override(
    resolved: &mut crate::config::extended::GoalSupervisionConfig,
    override_: &GoalSettingsOverride,
) {
    if let Some(default_token_budget) = override_.default_token_budget {
        resolved.default_token_budget = default_token_budget;
    }
    if let Some(model) = &override_.planner_model {
        resolved.planner_model = Some(model.trim().to_string());
    }
    if let Some(model) = &override_.evaluator_model {
        resolved.evaluator_model = Some(model.trim().to_string());
    }
    if let Some(model) = &override_.gatekeeper_model {
        resolved.gatekeeper_model = Some(model.trim().to_string());
    }
    if let Some(cold_skeptic_count) = override_.cold_skeptic_count {
        resolved.cold_skeptic_count = cold_skeptic_count;
    }
    if let Some(cold_skeptic_model) = &override_.cold_skeptic_model {
        resolved.cold_skeptic_model = Some(cold_skeptic_model.trim().to_string());
    }
    if let Some(max_verification_attempts) = override_.max_verification_attempts {
        resolved.max_verification_attempts = max_verification_attempts;
    }
}

fn tool_family(name: &str) -> &'static str {
    match name {
        "read" | "write" | "edit" | "unlock" => "files",
        "context_pack" | "code" | "graph" | "search" | "change_impact" | "lsp" => "code intel",
        "bash" | "escalate" | "harness_list" | "harness_invoke" => "execution",
        "task"
        | "spawn"
        | "return"
        | "question"
        | "defer_to_orchestrator"
        | "schedule"
        | "start_build" => "coordination",
        "session_search" | "session_read" | "session_lineage_search" | "todo" => "memory",
        "skill" | "skill_manage" | "mcp" => "extensions",
        "grep" | "glob" => "sandbox",
        _ => "other",
    }
}

/// A markdown agent's per-agent description override for one tool. Authored in
/// `tool_descriptions:` frontmatter either as one canonical string or as a
/// canonical string plus optional verbose steering text:
///
/// ```yaml
/// tool_descriptions:
///   task:
///     text: "Delegate substantive work here."
///     verboseText: "Hand each well-scoped piece to a subagent …"
/// ```
///
/// A bare string applies to both steering renderings. The object form applies
/// `text` to terse steering and `verboseText`, when present, to verbose
/// steering; when `verboseText` is omitted, the canonical `text` is used for
/// both.
///
/// Only the *description text* is selected; the tool's ID and SCHEMA are
/// never affected (schema variation would change validation/repair behavior).
///
/// Deserialization stays hand-written so the closed object schema is identical
/// under YAML and JSON. The retired `{normal, frontier, defensive}` shape is a
/// hard error; this prelaunch cleanup intentionally has no compatibility shim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolDescriptionSpec {
    /// A single canonical description text, applied to both steerings.
    Text(String),
    /// Canonical terse text plus optional verbose steering text.
    WithVerbose {
        text: String,
        verbose_text: Option<String>,
    },
}

impl Serialize for ToolDescriptionSpec {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        match self {
            ToolDescriptionSpec::Text(text) => ser.serialize_str(text),
            ToolDescriptionSpec::WithVerbose { text, verbose_text } => {
                let len = 1 + usize::from(verbose_text.is_some());
                let mut map = ser.serialize_map(Some(len))?;
                map.serialize_entry("text", text)?;
                if let Some(verbose) = verbose_text {
                    map.serialize_entry("verboseText", verbose)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for ToolDescriptionSpec {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        struct SpecVisitor;
        impl<'de> serde::de::Visitor<'de> for SpecVisitor {
            type Value = ToolDescriptionSpec;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a bare string or a `{text, verboseText?}` map")
            }
            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> std::result::Result<Self::Value, E> {
                Ok(ToolDescriptionSpec::Text(v.to_string()))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                v: String,
            ) -> std::result::Result<Self::Value, E> {
                Ok(ToolDescriptionSpec::Text(v))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut text: Option<String> = None;
                let mut verbose_text: Option<String> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "text" => text = map.next_value()?,
                        "verboseText" => verbose_text = map.next_value()?,
                        other => {
                            return Err(serde::de::Error::custom(format!(
                                "unknown tool-description key `{other}` (expected `text` or `verboseText`)"
                            )));
                        }
                    }
                }
                let text = text.ok_or_else(|| {
                    serde::de::Error::custom("tool-description object requires non-empty `text`")
                })?;
                if text.trim().is_empty() {
                    return Err(serde::de::Error::custom(
                        "tool-description object requires non-empty `text`",
                    ));
                }
                if verbose_text
                    .as_ref()
                    .is_some_and(|value| value.trim().is_empty())
                {
                    return Err(serde::de::Error::custom(
                        "tool-description `verboseText` must be non-empty when present",
                    ));
                }
                Ok(ToolDescriptionSpec::WithVerbose { text, verbose_text })
            }
        }
        de.deserialize_any(SpecVisitor)
    }
}

impl ToolDescriptionSpec {
    /// Project to the engine-level [`crate::engine::tool::ToolDescOverride`].
    /// A bare `Text` maps to both renderings. `WithVerbose` preserves the
    /// canonical text for both renderings unless it carries explicit verbose
    /// prose.
    pub fn to_override(&self) -> crate::engine::tool::ToolDescOverride {
        match self {
            ToolDescriptionSpec::Text(text) => crate::engine::tool::ToolDescOverride {
                text: Some(text.clone()),
                verbose_text: Some(text.clone()),
            },
            ToolDescriptionSpec::WithVerbose { text, verbose_text } => {
                crate::engine::tool::ToolDescOverride {
                    text: Some(text.clone()),
                    verbose_text: Some(verbose_text.as_ref().unwrap_or(text).clone()),
                }
            }
        }
    }
}

fn deserialize_tool_descriptions<'de, D>(
    de: D,
) -> std::result::Result<BTreeMap<String, ToolDescriptionSpec>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct ToolDescriptionsVisitor;

    impl<'de> serde::de::Visitor<'de> for ToolDescriptionsVisitor {
        type Value = BTreeMap<String, ToolDescriptionSpec>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a map of tool names to bare strings or `{text, verboseText?}` maps")
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut out = BTreeMap::new();
            while let Some(tool) = map.next_key::<String>()? {
                // `serde_yaml` already records the enclosing map key in its
                // diagnostic path. Re-prefixing this error produces the
                // confusing duplicate `tool_descriptions.<tool>` path while
                // losing no useful validation context.
                let spec = map.next_value::<ToolDescriptionSpec>()?;
                out.insert(tool, spec);
            }
            Ok(out)
        }
    }

    de.deserialize_map(ToolDescriptionsVisitor)
}

/// Reachability of an agent in the delegation tree. This is an execution-role
/// classification, not model selection or posture.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AgentMode {
    /// Reachable both as a primary (chat-owning) agent and as a `task`
    /// subagent.
    #[default]
    All,
    /// Reachable only as a primary chat-owning agent.
    Primary,
    /// Reachable only as a `task` subagent.
    Subagent,
}

impl AgentMode {
    /// Whether this agent may be delegated to via `task` (i.e. it is a
    /// reachable subagent). The `Primary`/`All` distinction for chat
    /// ownership is consumed by primary selection; subagent reachability is
    /// consumed by delegation.
    pub fn is_subagent(self) -> bool {
        matches!(self, AgentMode::All | AgentMode::Subagent)
    }

    /// Whether this agent may own the chat as a primary (top-level) agent —
    /// i.e. it is a valid `/agent` switch / `Shift+Tab` cycle target. `All`
    /// and `Primary` are chat-ownable; a `Subagent` is never. The inverse of
    /// "subagent-only" (`builder`/`explore`/`docs`).
    pub fn is_chat_ownable(self) -> bool {
        matches!(self, AgentMode::All | AgentMode::Primary)
    }
}

/// The chat-owning (primary) agents in their canonical cycle / listing
/// order: the two public builtins first (`Plan`, `Build`), then every
/// user-defined chat-ownable agent (mode `primary` or `all`, excluding the
/// builtins) in alphabetical order by name. Drives both the `/agent` valid-
/// choices list and the `Shift+Tab` cycle (`agent-switch-command-
/// and-cycle.md`). Custom agents whose file failed to parse are skipped —
/// they cannot be resolved as a switch target. Subagents are never included.
pub fn chat_ownable_primaries(cwd: &Path) -> Vec<String> {
    chat_ownable_primaries_with(cwd)
}

fn chat_ownable_primaries_with(cwd: &Path) -> Vec<String> {
    // Builtins first, in the prompt-specified cycle order — note this is
    // intentionally *not* `BUILTIN_AGENT_NAMES` order (which interleaves the
    // subagents) nor the settings toggle's order.
    let mut out: Vec<String> = builtin_defs::PUBLIC_PRIMARY_NAMES
        .iter()
        .filter(|name| !is_hidden_primary(name))
        .map(|name| (*name).to_string())
        .collect();

    // User-defined chat-ownable agents, alphabetical by name. `list_all`
    // already de-dupes and folds built-in overrides into the built-in entry,
    // so a custom name here is genuinely non-builtin.
    let mut custom: Vec<String> = list_all(cwd)
        .into_iter()
        .filter(|listing| matches!(listing.kind, AgentKind::Custom))
        .filter_map(|listing| match listing.def {
            Ok(def)
                if def.vnext.as_ref().is_some_and(|definition| {
                    definition.execution_kind == ExecutionKind::Assistant
                }) || def.vnext.is_none() && def.mode.is_chat_ownable() =>
            {
                Some(listing.name)
            }
            _ => None,
        })
        .collect();
    custom.sort();
    out.extend(custom);
    out
}

/// The next primary agent in the wrapping cycle, given the currently active
/// agent `current` and the ordered cycle list `order` (as built by
/// [`chat_ownable_primaries`]). Pure so the cycle order is unit-testable
/// without an `App`. When `current` is not in `order` (e.g. the chat is on a
/// subagent, or the active name is stale) the cycle starts at the front.
/// An empty `order` returns `current` unchanged (no-op).
pub fn next_primary_in_cycle(current: &str, order: &[String]) -> String {
    if order.is_empty() {
        return current.to_string();
    }
    match order.iter().position(|n| n == current) {
        Some(idx) => order[(idx + 1) % order.len()].clone(),
        None => order[0].clone(),
    }
}

impl AgentDef {
    /// Non-fatal diagnostics emitted by the local definition loader. Keeping
    /// these separate from invariant errors lets loading warn without silently
    /// changing the definition's grants.
    pub fn load_warnings(&self) -> Vec<String> {
        invariants::small_model_capability_warning(self)
            .into_iter()
            .collect()
    }

    /// Warn when an explicit runtime model override falls outside every model
    /// suggested by this definition. Suggestions are advisory: this never
    /// changes capabilities, tools, steering, or context policy.
    pub fn model_override_warning(&self, provider: &str, model: &str) -> Option<String> {
        let vnext = self.vnext.as_ref()?;
        let suggestions = vnext
            .model_slots
            .values()
            .flat_map(|slot| slot.suggested_models.iter())
            .collect::<Vec<_>>();
        if suggestions.is_empty() {
            return None;
        }
        let qualified = format!("{provider}/{model}");
        let matches = suggestions.iter().any(|recommendation| {
            recommendation.upstream_identity == qualified
                || recommendation.upstream_identity == model
                || recommendation
                    .provider_aliases
                    .iter()
                    .any(|alias| alias.provider_id == provider && alias.model_id == model)
        });
        (!matches).then(|| {
            format!(
                "agent `{}` is using explicit model override `{qualified}`, which is outside its suggested models; posture and capability grants are unchanged",
                self.name
            )
        })
    }

    /// The agent's effective system prompt (issue #75). The canonical body
    /// is [`Self::prompt`]; when [`Self::prompt_overrides`] carries a body
    /// for the given `model_hint` (matched by model-slot name or model id),
    /// that override wins. A flat-file or embedded agent has no overrides, so
    /// this is always [`Self::prompt`]. Resolution funnels here rather than
    /// reading `self.prompt` at scattered sites.
    pub fn resolved_prompt(&self, model_hint: Option<&str>) -> &str {
        if let Some(hint) = model_hint {
            if let Some(body) = self.prompt_overrides.get(hint) {
                return body;
            }
        }
        &self.prompt
    }

    /// Resolve the most specific prompt body for a concrete model. Exact
    /// provider/model and bare model-id overrides win; otherwise a matching
    /// vNext slot override applies, with `primary` as the execution slot used
    /// by ordinary agent construction.
    pub fn resolved_prompt_for_model(&self, provider: &str, model: &str) -> &str {
        let qualified = format!("{provider}/{model}");
        if let Some(body) = self.prompt_overrides.get(&qualified) {
            return body;
        }
        if let Some(body) = self.prompt_overrides.get(model) {
            return body;
        }
        if let Some(vnext) = &self.vnext {
            for (slot_id, slot) in &vnext.model_slots {
                let matches = slot.suggested_models.iter().any(|recommendation| {
                    recommendation.upstream_identity == qualified
                        || recommendation.upstream_identity == model
                        || recommendation
                            .provider_aliases
                            .iter()
                            .any(|alias| alias.provider_id == provider && alias.model_id == model)
                });
                if matches && let Some(body) = self.prompt_overrides.get(slot_id) {
                    return body;
                }
            }
            if vnext.model_slots.contains_key("primary")
                && let Some(body) = self.prompt_overrides.get("primary")
            {
                return body;
            }
        }
        &self.prompt
    }

    /// Serialize back to the on-disk `<name>.md` form: YAML frontmatter
    /// fence + the markdown body. Used by eject so a built-in's default
    /// materializes as a faithful, re-editable file.
    pub fn to_markdown(&self) -> Result<String> {
        if self.vnext.is_some() {
            let yaml = self.vnext_canonical_frontmatter()?;
            let body = self.prompt.trim_end_matches('\n');
            return Ok(format!("---\n{yaml}---\n\n{body}\n"));
        }
        // Build an ordered frontmatter map so the emitted file is stable
        // and human-friendly (description, mode, model, temperature,
        // tools, permission — only the fields that carry a value).
        let mut fm = serde_yaml::Mapping::new();
        fm.insert("description".into(), self.description.clone().into());
        fm.insert(
            "mode".into(),
            serde_yaml::to_value(self.mode)?
                .as_str()
                .unwrap_or("all")
                .into(),
        );
        if let Some(model) = &self.model {
            fm.insert("model".into(), model.clone().into());
        }
        if let Some(temp) = self.temperature {
            fm.insert("temperature".into(), (temp as f64).into());
        }
        if let Some(tools) = &self.tools {
            let seq: Vec<serde_yaml::Value> = tools.iter().map(|t| t.clone().into()).collect();
            fm.insert("tools".into(), serde_yaml::Value::Sequence(seq));
        }
        if !self.tool_tiers.is_empty() {
            fm.insert("toolTiers".into(), serde_yaml::to_value(&self.tool_tiers)?);
        }
        if !self.tool_descriptions.is_empty() {
            fm.insert(
                "tool_descriptions".into(),
                serde_yaml::to_value(&self.tool_descriptions)?,
            );
        }
        if let Some(scan) = self.scan_tool_results {
            fm.insert("scanToolResults".into(), scan.into());
        }
        if !self.goal_supervision.is_empty() {
            fm.insert(
                "goalSupervision".into(),
                serde_yaml::to_value(&self.goal_supervision)?,
            );
        }
        if let Some(perm) = &self.permission {
            fm.insert("permission".into(), serde_yaml::to_value(perm)?);
        }
        if let Some(caps) = &self.capabilities {
            fm.insert("capabilities".into(), serde_yaml::to_value(caps)?);
        }
        if let Some(steering) = self.tool_steering {
            fm.insert("toolSteering".into(), serde_yaml::to_value(steering)?);
        }
        if let Some(policy) = &self.context_policy {
            fm.insert("contextPolicy".into(), serde_yaml::to_value(policy)?);
        }
        let yaml = serde_yaml::to_string(&serde_yaml::Value::Mapping(fm))?;
        let body = self.prompt.trim_end_matches('\n');
        Ok(format!("---\n{yaml}---\n\n{body}\n"))
    }

    /// The exact UTF-8 frontmatter bytes that identify a vNext definition.
    /// The caller that persists a definition digest hashes these bytes rather
    /// than raw authored YAML, so mapping insertion order cannot change the
    /// identity of an otherwise equivalent closed-schema definition.
    pub fn vnext_digest_bytes(&self) -> Result<Vec<u8>> {
        if let Some(files) = &self.package_files {
            // Package identity is whole-tree: sorted relative paths plus the
            // exact contents of every file. Single-file defs must not take
            // this branch — their preimage stays `to_markdown()` bytes.
            return Ok(package_digest_preimage(files));
        }
        // The prompt body is part of the definition's authority-free but
        // behaviorally material contract.  Hash the complete canonical
        // markdown document rather than frontmatter alone.
        self.to_markdown().map(String::into_bytes)
    }

    /// True when this definition was loaded from a directory package.
    pub fn is_package(&self) -> bool {
        self.package_files.is_some()
    }

    /// Resolve this definition's vNext grant, attaching package-private child
    /// identities so `permits_child` / reachable-subagent lookup prefer them
    /// over a same-named global agent.
    pub fn resolve_vnext_grant(&self, host: &VnextHostPolicy) -> Result<EffectiveVnextGrant> {
        let vnext = self
            .vnext
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("vNext grant requires a schemaVersion 2 definition"))?;
        let mut grant = vnext.resolve_grant(host)?;
        if let Some(delegation) = &mut grant.delegation {
            let mut package_definitions = BTreeMap::new();
            for (name, child) in &self.private_subagents {
                if let Some(child_vnext) = &child.vnext {
                    if delegation
                        .package_children
                        .insert(name.clone(), child_vnext.agent_id.clone())
                        .is_some()
                    {
                        bail!("package-private subagent `{name}` is not unique");
                    }
                    if child_vnext.agent_id != *name {
                        ensure!(
                            delegation
                                .package_children
                                .insert(child_vnext.agent_id.clone(), child_vnext.agent_id.clone())
                                .is_none(),
                            "package-private subagent identity `{}` is not unique",
                            child_vnext.agent_id
                        );
                    }
                    ensure!(
                        package_definitions
                            .insert(name.clone(), child.clone())
                            .is_none(),
                        "package-private subagent route `{name}` is not unique"
                    );
                    if child_vnext.agent_id != *name {
                        ensure!(
                            package_definitions
                                .insert(child_vnext.agent_id.clone(), child.clone())
                                .is_none(),
                            "package-private subagent route `{}` is not unique",
                            child_vnext.agent_id
                        );
                    }
                }
            }
            if delegation
                .allowed_children
                .iter()
                .any(AllowedChild::is_self)
            {
                package_definitions.insert(SELF_CHILD_REF.to_string(), self.clone());
            }
            delegation.package_definitions =
                vnext::PackageDefinitionSnapshot(std::sync::Arc::new(package_definitions));
        }
        Ok(grant)
    }

    /// Source-agent identity for a package-private child bound with its parent.
    pub fn package_child_source_agent_id(parent_source_agent_id: &str, child_name: &str) -> String {
        format!("{parent_source_agent_id}/{child_name}")
    }

    fn vnext_canonical_frontmatter(&self) -> Result<String> {
        let vnext = self
            .vnext
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("legacy agent definitions have no vNext digest"))?;
        vnext.validate()?;
        let mut fm = serde_yaml::Mapping::new();
        fm.insert("schemaVersion".into(), (vnext.schema_version as u64).into());
        fm.insert("agentId".into(), vnext.agent_id.clone().into());
        fm.insert(
            "executionKind".into(),
            serde_yaml::to_value(vnext.execution_kind)?,
        );
        fm.insert(
            "modelSlots".into(),
            serde_yaml::to_value(&vnext.model_slots)?,
        );
        if !vnext.delegation.is_off() {
            fm.insert(
                "delegation".into(),
                serde_yaml::to_value(&vnext.delegation)?,
            );
        }
        if let Some(questions) = &vnext.questions {
            fm.insert("questions".into(), serde_yaml::to_value(questions)?);
        }
        if let Some(verification) = &vnext.verification {
            fm.insert("verification".into(), serde_yaml::to_value(verification)?);
        }
        if let Some(capabilities) = &self.capabilities {
            fm.insert("capabilities".into(), serde_yaml::to_value(capabilities)?);
        }
        if let Some(tool_steering) = self.tool_steering {
            fm.insert("toolSteering".into(), serde_yaml::to_value(tool_steering)?);
        }
        if let Some(context_policy) = &self.context_policy {
            fm.insert(
                "contextPolicy".into(),
                serde_yaml::to_value(context_policy)?,
            );
        }
        // Description remains display metadata, never an authority input.
        fm.insert("description".into(), self.description.clone().into());
        let mut value = serde_yaml::Value::Mapping(fm);
        canonicalize_yaml_mapping_keys(&mut value);
        Ok(serde_yaml::to_string(&value)?)
    }
}

/// serde's struct serializers preserve declaration order.  vNext stores only
/// closed-schema values, so normalize every map recursively before emitting
/// the definition's canonical digest/round-trip form.
fn canonicalize_yaml_mapping_keys(value: &mut serde_yaml::Value) {
    match value {
        serde_yaml::Value::Mapping(mapping) => {
            let mut entries: Vec<_> = mapping
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            for (_, nested) in &mut entries {
                canonicalize_yaml_mapping_keys(nested);
            }
            entries.sort_by(|(left, _), (right, _)| {
                left.as_str()
                    .unwrap_or_default()
                    .cmp(right.as_str().unwrap_or_default())
            });
            mapping.clear();
            for (key, nested) in entries {
                mapping.insert(key, nested);
            }
        }
        serde_yaml::Value::Sequence(values) => {
            for nested in values {
                canonicalize_yaml_mapping_keys(nested);
            }
        }
        _ => {}
    }
}

/// Split a `<frontmatter>\n---\n<body>` markdown document into the raw
/// YAML frontmatter and the body. A document with no leading `---` fence
/// has an empty frontmatter and the whole text as body. The opening
/// fence must be the very first line.
fn split_frontmatter(text: &str) -> (&str, &str) {
    let rest = match text.strip_prefix("---\n") {
        Some(r) => r,
        // Tolerate a leading BOM / CRLF opening fence.
        None => match text.strip_prefix("---\r\n") {
            Some(r) => r,
            None => return ("", text),
        },
    };
    // Scan for the closing fence: a line that is exactly `---`.
    let mut offset = 0usize;
    for line in rest.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\n', '\r']);
        if trimmed == "---" {
            let fm = &rest[..offset];
            let body = &rest[offset + line.len()..];
            return (fm, body);
        }
        offset += line.len();
    }
    // No closing fence — treat the whole remainder as frontmatter-less.
    ("", text)
}

/// Parse YAML frontmatter + markdown body into an [`AgentDef`]. `name`
/// is the resolved agent name (the file stem); `source` is the path the
/// text came from (used in diagnostics). A missing `description` or bad
/// YAML fails with the `source` path named so the user's mistake isn't
/// hidden.
pub fn parse_agent(text: &str, name: &str, source: PathBuf) -> Result<AgentDef> {
    parse_agent_with_scope(text, name, source, DefinitionScope::Workspace)
}

/// Parse a daemon-served agent snapshot.  The daemon is a trusted source for
/// all publisher provenances (`cockpit`, `authored`, `local`), so this uses
/// [`DefinitionScope::DaemonSnapshot`] which accepts any publisher without
/// re-checking the loader boundary.  Callers must only use this for markdown
/// that arrived over a daemon RPC — never for workspace files.
pub fn parse_daemon_agent_snapshot(text: &str, name: &str, source: PathBuf) -> Result<AgentDef> {
    parse_agent_with_scope(text, name, source, DefinitionScope::DaemonSnapshot)
}

/// Parse a definition with origin supplied by its trusted owner. The only
/// daemon-local owner today is the persisted assistant loader; all ordinary
/// workspace paths use [`parse_agent`] and cannot claim the `local` publisher.
fn parse_agent_with_scope(
    text: &str,
    name: &str,
    source: PathBuf,
    scope: DefinitionScope,
) -> Result<AgentDef> {
    let (fm_raw, body) = split_frontmatter(text);

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Frontmatter {
        #[serde(rename = "schemaVersion", default)]
        schema_version: Option<u8>,
        #[serde(rename = "agentId", default)]
        agent_id: Option<String>,
        #[serde(rename = "executionKind", default)]
        execution_kind: Option<ExecutionKind>,
        #[serde(rename = "modelSlots", default)]
        model_slots: Option<BTreeMap<String, ModelSlot>>,
        #[serde(default)]
        delegation: Option<DelegationPolicy>,
        #[serde(default)]
        questions: Option<QuestionPolicy>,
        #[serde(default)]
        verification: Option<VerificationPolicy>,
        #[serde(default)]
        description: String,
        #[serde(default)]
        mode: AgentMode,
        #[serde(default)]
        model: Option<String>,
        #[serde(default)]
        temperature: Option<f32>,
        #[serde(default)]
        tools: Option<Vec<String>>,
        #[serde(rename = "toolTiers", default)]
        tool_tiers: BTreeMap<String, ToolTier>,
        #[serde(default, deserialize_with = "deserialize_tool_descriptions")]
        tool_descriptions: BTreeMap<String, ToolDescriptionSpec>,
        #[serde(rename = "scanToolResults", default)]
        scan_tool_results: Option<bool>,
        #[serde(rename = "goalSupervision", default)]
        goal_supervision: GoalSettingsOverride,
        #[serde(default)]
        permission: Option<serde_json::Value>,
        #[serde(default)]
        capabilities: Option<BTreeSet<AgentCapability>>,
        #[serde(rename = "toolSteering", default)]
        tool_steering: Option<ToolSteering>,
        #[serde(rename = "contextPolicy", default)]
        context_policy: Option<ContextPolicy>,
    }

    if fm_raw.trim().is_empty() {
        bail!(
            "agent `{name}` ({}) has no YAML frontmatter — a `description` field is required",
            source.display()
        );
    }
    // `questions` and `verification` are closed optional objects: omission is
    // the only spelling for off.  Accepting YAML `null` would create a second,
    // ambiguous wire representation that profile reduction could accidentally
    // reinterpret as enabled later.
    let raw_frontmatter: serde_yaml::Value = serde_yaml::from_str(fm_raw).map_err(|e| {
        anyhow::anyhow!(
            "agent `{name}` ({}) has invalid frontmatter: {e}",
            source.display()
        )
    })?;
    let raw_keys = if let serde_yaml::Value::Mapping(mapping) = &raw_frontmatter {
        if mapping
            .get(serde_yaml::Value::String("schemaVersion".to_string()))
            .is_some_and(serde_yaml::Value::is_null)
        {
            bail!(
                "agent `{name}` ({}) must declare schemaVersion: 2; null is not accepted",
                source.display()
            );
        }
        for key in ["delegation", "questions", "verification"] {
            if mapping
                .get(serde_yaml::Value::String(key.to_string()))
                .is_some_and(serde_yaml::Value::is_null)
            {
                bail!(
                    "agent `{name}` ({}) must omit `{key}` to disable it; null is not accepted",
                    source.display()
                );
            }
        }
        mapping
            .keys()
            .filter_map(serde_yaml::Value::as_str)
            .collect::<BTreeSet<_>>()
    } else {
        bail!(
            "agent `{name}` ({}) frontmatter must be a YAML mapping",
            source.display()
        );
    };
    let fm: Frontmatter = serde_yaml::from_str(fm_raw).map_err(|e| {
        anyhow::anyhow!(
            "agent `{name}` ({}) has invalid frontmatter: {e}",
            source.display()
        )
    })?;
    if fm.description.trim().is_empty() {
        bail!(
            "agent `{name}` ({}) is missing a non-empty `description`",
            source.display()
        );
    }

    let vnext = match fm.schema_version {
        Some(SCHEMA_VERSION) => {
            // Presence is the wire contract here, not the deserialized
            // value.  In particular `mode: all`, `forkEligible: false`, and
            // every `null` legacy spelling must be rejected rather than
            // silently becoming a v2 default.
            const LEGACY_V1_KEYS: &[&str] = &[
                "mode",
                "model",
                "temperature",
                "tools",
                "toolTiers",
                "tool_descriptions",
                "toolDescriptions",
                "scanToolResults",
                "goalSupervision",
                "permission",
                "forkEligible",
            ];
            if let Some(field) = LEGACY_V1_KEYS.iter().find(|key| raw_keys.contains(*key)) {
                bail!(
                    "agent `{name}` ({}) is schemaVersion 2 and may not declare legacy field `{field}`",
                    source.display(),
                );
            }
            let definition = VnextAgentDef {
                schema_version: SCHEMA_VERSION,
                agent_id: fm.agent_id.ok_or_else(|| {
                    anyhow::anyhow!(
                        "agent `{name}` ({}) schemaVersion 2 requires agentId",
                        source.display()
                    )
                })?,
                execution_kind: fm.execution_kind.ok_or_else(|| {
                    anyhow::anyhow!(
                        "agent `{name}` ({}) schemaVersion 2 requires executionKind",
                        source.display()
                    )
                })?,
                model_slots: fm.model_slots.ok_or_else(|| {
                    anyhow::anyhow!(
                        "agent `{name}` ({}) schemaVersion 2 requires modelSlots",
                        source.display()
                    )
                })?,
                delegation: fm.delegation.unwrap_or_default(),
                questions: fm.questions,
                verification: fm.verification,
            };
            definition.validate_for_scope(scope).map_err(|error| {
                anyhow::anyhow!(
                    "agent `{name}` ({}) has invalid schemaVersion 2 definition: {error}",
                    source.display()
                )
            })?;
            Some(definition)
        }
        Some(version) => bail!(
            "agent `{name}` ({}) has unsupported schemaVersion `{version}`; only 2 is accepted",
            source.display()
        ),
        None => bail!(
            "agent `{name}` ({}) must declare schemaVersion: 2; legacy schema-less user AgentDefs are no longer supported",
            source.display()
        ),
    };

    Ok(AgentDef {
        name: name.to_string(),
        description: fm.description,
        // `mode` belongs exclusively to the retired schema.  It remains as an
        // internal field only while embedded legacy definitions exist; a v2
        // document is classified from `executionKind` at every discovery and
        // runtime reachability seam, never translated into a legacy mode.
        mode: fm.mode,
        model: fm.model,
        temperature: fm.temperature,
        tools: fm.tools,
        tool_tiers: fm.tool_tiers,
        tool_descriptions: fm.tool_descriptions,
        scan_tool_results: fm.scan_tool_results,
        goal_supervision: fm.goal_supervision,
        permission: fm.permission,
        capabilities: fm.capabilities,
        tool_steering: fm.tool_steering,
        context_policy: fm.context_policy,
        vnext,
        // Trim the blank line(s) the frontmatter fence leaves before the
        // body and any trailing newline, so the stored prompt matches the
        // embedded-default form (the composer re-adds a single newline).
        prompt: body.trim_start_matches('\n').trim_end().to_string(),
        prompt_overrides: std::collections::BTreeMap::new(),
        package_files: None,
        private_subagents: BTreeMap::new(),
        source,
    })
}

/// Canonical whole-tree digest preimage: each file is length-prefixed path
/// then length-prefixed contents, in sorted relative-path order. Changing any
/// file, adding one, or renaming one changes the preimage.
pub(crate) fn package_digest_preimage(files: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    for (path, content) in files {
        let path_bytes = path.as_bytes();
        out.extend_from_slice(&(path_bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(path_bytes);
        out.extend_from_slice(&(content.len() as u64).to_be_bytes());
        out.extend_from_slice(content);
    }
    out
}

pub fn default_scan_tool_results(name: &str) -> bool {
    !matches!(name, "explore" | "scout" | "docs-answerer")
}

/// Load a single agent file from an arbitrary path. The file does not
/// need to live in any particular directory. Used by `cockpit run
/// --agent-file …`. The agent name is the file stem.
pub fn load_from_file(path: &Path) -> Result<AgentDef> {
    let text = read_agent_markdown(path)?;
    let name = agent_name_from_path(path)
        .ok_or_else(|| anyhow::anyhow!("agent file {} has no usable file stem", path.display()))?;
    let def = parse_agent(&text, &name, path.to_path_buf())?;
    validate_loaded_def(&def)?;
    Ok(def)
}

/// Load an agent-shaped markdown file while supplying the resolved logical
/// name from an owning entity. Assistants use this for
/// `<assistant-home>/assistant.md`: the file shape and validation stay exactly
/// the same as agents, while the persisted assistant name remains the entity
/// identity instead of the literal `assistant.md` stem.
pub fn load_workspace_named_from_file(path: &Path, name: &str) -> Result<AgentDef> {
    let text = read_agent_markdown(path)?;
    let def = parse_agent(&text, name, path.to_path_buf())?;
    validate_loaded_def(&def)?;
    Ok(def)
}

/// Load the on-disk override for one exact embedded definition.  Ejected
/// built-ins retain their `cockpit/<name>` portable identity so child refs and
/// the digest contract survive editing.  That publisher is never accepted by
/// ordinary workspace discovery: this narrow loader is called only after the
/// resolver has established that `name` is a built-in and `path` is its
/// override path.
fn load_builtin_override_from_file(path: &Path, name: &str) -> Result<AgentDef> {
    let text = read_agent_markdown(path)?;
    let def = parse_agent_with_scope(
        &text,
        name,
        path.to_path_buf(),
        DefinitionScope::BuiltinOverride,
    )?;
    let expected_id = format!("cockpit/{}", name.to_ascii_lowercase());
    if def.vnext.as_ref().map(|vnext| vnext.agent_id.as_str()) != Some(expected_id.as_str()) {
        bail!(
            "built-in override `{name}` ({}) must retain its trusted agentId `{expected_id}`",
            path.display()
        );
    }
    validate_loaded_def(&def)?;
    Ok(def)
}

fn load_builtin_override_from_dir(dir: &Path, name: &str) -> Result<AgentDef> {
    let def = load_from_dir(dir, name, DefinitionScope::BuiltinOverride)?;
    let expected_id = format!("cockpit/{}", name.to_ascii_lowercase());
    if def.vnext.as_ref().map(|vnext| vnext.agent_id.as_str()) != Some(expected_id.as_str()) {
        bail!("built-in package override `{name}` must retain its trusted agentId `{expected_id}`");
    }
    Ok(def)
}

/// Load an agent-shaped file from daemon-owned installation storage.  This is
/// intentionally separate from the workspace named-file loader so a TUI
/// display name can never confer daemon-local provenance on a checkout file.
pub fn load_daemon_local_named_from_file(path: &Path, name: &str) -> Result<AgentDef> {
    let text = read_agent_markdown(path)?;
    let def = parse_agent_with_scope(
        &text,
        name,
        path.to_path_buf(),
        DefinitionScope::DaemonLocal,
    )?;
    validate_loaded_def(&def)?;
    Ok(def)
}

/// Validate exact markdown bytes for a daemon-owned assistant definition
/// without requiring a client-visible or temporary authoritative path.
pub fn parse_daemon_local_markdown(text: &str, name: &str) -> Result<AgentDef> {
    let def = parse_agent_with_scope(
        text,
        name,
        PathBuf::from("<daemon-assistant-definition>"),
        DefinitionScope::DaemonLocal,
    )?;
    validate_loaded_def(&def)?;
    Ok(def)
}

/// Load exactly the daemon-owned path recorded for one selected installation
/// into the profile catalog.  This deliberately takes the installation UUID
/// and observation receipt from the installation service: display names are
/// diagnostics only and are never used to rediscover a same-named candidate.
///
/// Built-ins remain on their protected override loader, which verifies the
/// canonical `cockpit/<name>` identity before the definition can enter the
/// catalog.  Every other source uses the supplied owned path exactly once.
pub fn load_profile_definition_from_owned_path(
    installation: cockpit_db::db::agent_installations::AgentInstallationRow,
    observation: cockpit_db::db::agent_installations::AgentObservationRow,
    source: AgentProfileInstallationSource,
    owned_path: &Path,
) -> Result<AgentProfileDefinition> {
    ensure!(
        matches!(
            (source, installation.scope),
            (
                AgentProfileInstallationSource::Global | AgentProfileInstallationSource::Builtin,
                cockpit_db::db::agent_installations::AgentInstallationScope::Global
            ) | (
                AgentProfileInstallationSource::WorkspacePrivate,
                cockpit_db::db::agent_installations::AgentInstallationScope::WorkspacePrivate
            )
        ),
        "pathname profile loading is restricted to daemon-owned installation scopes"
    );
    ensure!(
        observation.installation_id == installation.installation_id,
        "profile observation belongs to a different installation"
    );
    let launch_target = installation
        .source_agent_id
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .context("profile installation has no launch target name")?;
    let definition = if owned_path.is_dir() {
        let parent = owned_path
            .parent()
            .context("owned package path missing parent")?;
        let dir_name = owned_path
            .file_name()
            .and_then(|name| name.to_str())
            .context("owned package path has no directory name")?;
        load_from_dir(
            parent,
            dir_name,
            profile_definition_scope(source, &installation.source_agent_id),
        )?
    } else if owned_path.file_name().and_then(|name| name.to_str()) == Some(PACKAGE_ROOT_FILE) {
        let dir = owned_path
            .parent()
            .context("owned package agent.md missing parent")?;
        let parent = dir
            .parent()
            .context("owned package missing agents directory")?;
        let dir_name = dir
            .file_name()
            .and_then(|name| name.to_str())
            .context("owned package has no directory name")?;
        load_from_dir(
            parent,
            dir_name,
            profile_definition_scope(source, &installation.source_agent_id),
        )?
    } else {
        match source {
            AgentProfileInstallationSource::Builtin => {
                let name = installation
                    .source_agent_id
                    .strip_prefix("cockpit/")
                    .filter(|name| is_builtin_agent(name))
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "builtin installation has an unprotected source agent identity `{}`",
                            installation.source_agent_id
                        )
                    })?;
                load_builtin_override_from_file(owned_path, name)?
            }
            AgentProfileInstallationSource::Global
            | AgentProfileInstallationSource::WorkspacePrivate => {
                // The logical parse name and scope are daemon-owned metadata.
                // Read the retained leaf through the no-follow owned-path
                // loader: package children must never be reopened through the
                // ordinary workspace loader after the package tree was read.
                load_owned_definition(
                    owned_path,
                    launch_target,
                    profile_definition_scope(source, &installation.source_agent_id),
                )?
            }
            AgentProfileInstallationSource::WorkspaceShared => {
                unreachable!("workspace-shared source was rejected before pathname loading")
            }
        }
    };
    profile_definition_from_loaded(
        installation,
        observation,
        source,
        definition,
        "owned profile path",
    )
}

/// Finish a workspace-shared profile from bytes read through the attach-time
/// directory capability. This boundary deliberately accepts an already parsed
/// definition rather than a path, so startup, SetAgent, and private package
/// children cannot accidentally regain pathname authority.
pub(crate) fn profile_definition_from_workspace_snapshot(
    installation: cockpit_db::db::agent_installations::AgentInstallationRow,
    observation: cockpit_db::db::agent_installations::AgentObservationRow,
    definition: AgentDef,
) -> Result<AgentProfileDefinition> {
    ensure!(
        installation.scope
            == cockpit_db::db::agent_installations::AgentInstallationScope::WorkspaceShared,
        "attached workspace profile snapshot requires workspace-shared installation scope"
    );
    profile_definition_from_loaded(
        installation,
        observation,
        AgentProfileInstallationSource::WorkspaceShared,
        definition,
        "attached workspace profile snapshot",
    )
}

fn profile_definition_from_loaded(
    installation: cockpit_db::db::agent_installations::AgentInstallationRow,
    observation: cockpit_db::db::agent_installations::AgentObservationRow,
    source: AgentProfileInstallationSource,
    definition: AgentDef,
    label: &str,
) -> Result<AgentProfileDefinition> {
    ensure!(
        observation.installation_id == installation.installation_id,
        "profile observation belongs to a different installation"
    );
    let launch_target = installation
        .source_agent_id
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .context("profile installation has no launch target name")?;
    let vnext = definition
        .vnext
        .as_ref()
        .context("profile installation did not load a vNext AgentDef")?;
    ensure!(
        vnext.agent_id == installation.source_agent_id
            || installation.source_agent_id
                == AgentDef::package_child_source_agent_id(
                    installation
                        .source_agent_id
                        .rsplit_once('/')
                        .map(|(parent, _)| parent)
                        .unwrap_or(""),
                    &definition.name,
                )
            || installation
                .source_agent_id
                .ends_with(&format!("/{}", definition.name)),
        "{label} identity does not match its selected installation"
    );
    Ok(AgentProfileDefinition {
        installation,
        observation,
        source,
        definition,
    })
}

/// Load a directory-form agent. Two layouts share this entry:
///
/// * **Package** (`<dir>/<name>/agent.md`): root def plus optional
///   `subagents/<child>.md`, reserved `mcp.json`, and per-slot prompt
///   override `*.md` files. Whole-tree digest applies.
/// * **Legacy prompt-override dir** (`<dir>/<name>/<key>.md` plus optional
///   flat sibling `<dir>/<name>.md`): existing per-model bodies. Digest stays
///   the single-file `to_markdown()` preimage of the canonical def.
///
/// `dir` is the search directory, `name` the agent name; the directory
/// `<dir>/<name>/` must exist (caller checks).
fn profile_definition_scope(
    source: AgentProfileInstallationSource,
    source_agent_id: &str,
) -> DefinitionScope {
    match source {
        AgentProfileInstallationSource::WorkspaceShared => DefinitionScope::Workspace,
        AgentProfileInstallationSource::Builtin => DefinitionScope::BuiltinOverride,
        AgentProfileInstallationSource::Global
        | AgentProfileInstallationSource::WorkspacePrivate
            if source_agent_id.starts_with("local/") =>
        {
            DefinitionScope::DaemonLocal
        }
        AgentProfileInstallationSource::Global
        | AgentProfileInstallationSource::WorkspacePrivate => DefinitionScope::Workspace,
    }
}

fn load_from_dir(dir: &Path, name: &str, scope: DefinitionScope) -> Result<AgentDef> {
    let agent_dir = dir.join(name);
    if agent_dir.join(PACKAGE_ROOT_FILE).is_file() {
        return load_package(&agent_dir, name, scope);
    }
    load_legacy_prompt_override_dir(dir, name, &agent_dir, scope)
}

/// Load one daemon-owned definition without rediscovering layers. Both the
/// historical flat file and the package directory are accepted; callers must
/// already have authorized the path's parent.
pub(crate) fn load_owned_definition(
    path: &Path,
    name: &str,
    scope: DefinitionScope,
) -> Result<AgentDef> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("statting owned agent definition {}", path.display()))?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "owned agent definition may not be a symlink"
    );
    if metadata.is_dir() {
        let parent = path.parent().context("owned agent package has no parent")?;
        return load_from_dir(parent, name, scope);
    }
    ensure!(
        metadata.is_file(),
        "owned agent definition is not a regular file"
    );
    let bytes = cockpit_host::private_fs::read_owned_file_nofollow(
        path,
        "owned agent definition",
        MAX_MARKDOWN_BYTES,
    )
    .with_context(|| format!("reading owned agent definition {}", path.display()))?
    .context("owned agent definition disappeared while reading")?;
    let text = std::str::from_utf8(&bytes).context("owned agent definition is not UTF-8")?;
    let def = parse_agent_with_scope(text, name, path.to_path_buf(), scope)?;
    validate_loaded_def(&def)?;
    Ok(def)
}

fn load_package(agent_dir: &Path, name: &str, scope: DefinitionScope) -> Result<AgentDef> {
    let files = collect_package_files(agent_dir)?;
    load_package_from_files(agent_dir, name, scope, files)
}

/// Parse an already capability-held package snapshot. The caller owns tree
/// traversal and supplies the complete bounded relative-path map; parsing
/// never reopens a workspace pathname.
pub(crate) fn load_workspace_package_from_files(
    name: &str,
    files: BTreeMap<String, Vec<u8>>,
) -> Result<AgentDef> {
    load_package_from_files(
        Path::new("<attached-workspace-agent-package>"),
        name,
        DefinitionScope::Workspace,
        files,
    )
}

fn load_package_from_files(
    agent_dir: &Path,
    name: &str,
    scope: DefinitionScope,
    files: BTreeMap<String, Vec<u8>>,
) -> Result<AgentDef> {
    let root_bytes = files.get(PACKAGE_ROOT_FILE).ok_or_else(|| {
        anyhow::anyhow!(
            "agent package `{}` ({}) is missing {PACKAGE_ROOT_FILE}",
            name,
            agent_dir.display()
        )
    })?;
    let text = std::str::from_utf8(root_bytes).map_err(|e| {
        anyhow::anyhow!(
            "agent package `{}` ({PACKAGE_ROOT_FILE}) is not UTF-8: {e}",
            name
        )
    })?;
    let mut base = parse_agent_with_scope(text, name, agent_dir.join(PACKAGE_ROOT_FILE), scope)?;
    ensure!(
        name != SELF_CHILD_REF,
        "agent package `{name}` uses the reserved self-delegation identity"
    );

    // Validate the complete route namespace before constructing any route
    // maps. Both a filename alias and an authored agentId select a private
    // child, so either may collide with another child, the parent, or `self`.
    let mut package_identities = BTreeMap::new();
    package_identities.insert(
        SELF_CHILD_REF.to_string(),
        "the reserved self route".to_string(),
    );
    package_identities.insert(name.to_string(), "the package root alias".to_string());
    if let Some(root) = &base.vnext {
        package_identities.insert(
            root.agent_id.clone(),
            "the package root agentId".to_string(),
        );
    }

    let mut overrides = BTreeMap::new();
    let mut private_subagents = BTreeMap::new();
    for (rel, bytes) in &files {
        if rel == PACKAGE_ROOT_FILE || rel == PACKAGE_MCP_FILE {
            continue;
        }
        if let Some(child) = rel
            .strip_prefix(&format!("{PACKAGE_SUBAGENTS_DIR}/"))
            .filter(|rest| !rest.is_empty() && !rest.contains('/'))
            .and_then(|rest| rest.strip_suffix(".md"))
        {
            if child == name {
                bail!(
                    "agent package `{name}` ({}) has a private subagent that reuses the package name",
                    agent_dir.display()
                );
            }
            let child_text = std::str::from_utf8(bytes).map_err(|e| {
                anyhow::anyhow!(
                    "agent package `{name}` private subagent `{child}` is not UTF-8: {e}"
                )
            })?;
            let child_def = parse_agent_with_scope(
                child_text,
                child,
                agent_dir
                    .join(PACKAGE_SUBAGENTS_DIR)
                    .join(format!("{child}.md")),
                scope,
            )?;
            if child_def.mode == AgentMode::Primary {
                bail!(
                    "agent package `{name}` private subagent `{child}` cannot declare mode: primary"
                );
            }
            validate_invariants(&child_def)?;
            let child_vnext = child_def.vnext.as_ref().with_context(|| {
                format!(
                    "agent package `{name}` private subagent `{child}` must be a vNext definition"
                )
            })?;
            let child_identities =
                BTreeSet::from([child.to_string(), child_vnext.agent_id.clone()]);
            for identity in child_identities {
                if let Some(owner) = package_identities.get(&identity) {
                    bail!(
                        "agent package `{name}` private subagent `{child}` identity `{identity}` collides with {owner}"
                    );
                }
                package_identities.insert(
                    identity,
                    format!("private subagent `{child}` alias/agentId"),
                );
            }
            if private_subagents
                .insert(child.to_string(), child_def)
                .is_some()
            {
                bail!(
                    "agent package `{name}` ({}) has duplicate private subagent `{child}`",
                    agent_dir.display()
                );
            }
            continue;
        }
        if rel.contains('/') {
            // Nested support files (mcp.json already skipped) are digested
            // but not interpreted by this stage.
            continue;
        }
        if let Some(key) = rel.strip_suffix(".md").filter(|k| !k.is_empty()) {
            let text = std::str::from_utf8(bytes).map_err(|e| {
                anyhow::anyhow!("agent package `{name}` prompt override `{rel}` is not UTF-8: {e}")
            })?;
            let parsed = parse_agent_with_scope(text, name, agent_dir.join(rel), scope)?;
            overrides.insert(key.to_string(), parsed.prompt);
        }
    }

    base.source = agent_dir.to_path_buf();
    base.prompt_overrides = overrides;
    base.package_files = Some(files);
    base.private_subagents = private_subagents;
    if let Some(bytes) = base
        .package_files
        .as_ref()
        .and_then(|files| files.get(PACKAGE_MCP_FILE))
    {
        let text = std::str::from_utf8(bytes).map_err(|e| {
            anyhow::anyhow!("agent package `{name}` ({PACKAGE_MCP_FILE}) is not UTF-8: {e}")
        })?;
        crate::mcp::config::McpConfig::parse(text).with_context(|| {
            format!(
                "agent package `{name}` ({}) {PACKAGE_MCP_FILE}",
                agent_dir.display()
            )
        })?;
    }
    validate_invariants(&base)?;
    Ok(base)
}

fn collect_package_files(agent_dir: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    #[cfg(any(unix, windows))]
    {
        return cockpit_host::private_fs::read_nofollow_directory_tree(
            agent_dir,
            MAX_MARKDOWN_BYTES,
            MAX_PACKAGE_BYTES,
        )
        .map_err(anyhow::Error::from)
        .with_context(|| format!("reading agent package {}", agent_dir.display()));
    }
    #[cfg(not(any(unix, windows)))]
    {
        bail!(
            "agent package traversal is unavailable on this platform; refusing pathname-based fallback for {}",
            agent_dir.display()
        )
    }
}

fn load_legacy_prompt_override_dir(
    dir: &Path,
    name: &str,
    agent_dir: &Path,
    scope: DefinitionScope,
) -> Result<AgentDef> {
    // Model IDs commonly contain `/`, so nested paths such as
    // `anthropic/claude-opus.md` become the key `anthropic/claude-opus`.
    // Use the same no-follow, aggregate-byte, entry-count, and depth-bounded
    // tree snapshot as packages. Legacy directories are still workspace input
    // and must not retain their old unbounded pathname recursion.
    let mut overrides: BTreeMap<String, String> = BTreeMap::new();
    let mut first_override_def: Option<AgentDef> = None;
    let override_files = cockpit_host::private_fs::read_nofollow_directory_tree(
        agent_dir,
        MAX_MARKDOWN_BYTES,
        MAX_PACKAGE_BYTES,
    )
    .map_err(anyhow::Error::from)
    .with_context(|| format!("reading legacy agent override tree {}", agent_dir.display()))?;
    let override_bytes = override_files.values().try_fold(0_u64, |total, bytes| {
        total
            .checked_add(bytes.len() as u64)
            .context("legacy agent override byte count overflow")
    })?;
    for (relative, bytes) in override_files {
        let Some(key) = relative.strip_suffix(".md").filter(|key| !key.is_empty()) else {
            continue;
        };
        let path = agent_dir.join(&relative);
        let key = key.to_string();
        let text = std::str::from_utf8(&bytes)
            .with_context(|| format!("agent override {} is not UTF-8", path.display()))?;
        let parsed = parse_agent_with_scope(text, name, path.clone(), scope)?;
        overrides.insert(key, parsed.prompt.clone());
        if first_override_def.is_none() {
            first_override_def = Some(parsed);
        }
    }

    // The flat `<dir>/<name>.md` sibling — the canonical body + frontmatter
    // source.
    let flat_path = dir.join(format!("{name}.md"));
    let flat_def = if flat_path.is_file() {
        let text = read_agent_markdown(&flat_path)?;
        ensure!(
            override_bytes.saturating_add(text.len() as u64) <= MAX_PACKAGE_BYTES,
            "legacy agent `{name}` aggregate exceeds {MAX_PACKAGE_BYTES} byte limit"
        );
        Some(parse_agent_with_scope(
            &text,
            name,
            flat_path.clone(),
            scope,
        )?)
    } else {
        None
    };

    // A directory with no override files and no flat sibling is an
    // empty/malformed agent: error naming it.
    let mut base = match (flat_def.clone(), first_override_def) {
        (Some(def), _) => def,
        (None, Some(def)) => def,
        (None, None) => bail!(
            "agent `{name}` ({}) has no per-model override `.md` files and no flat `{name}.md` sibling",
            agent_dir.display()
        ),
    };

    base.source = agent_dir.to_path_buf();
    base.prompt_overrides = overrides;
    // The canonical flat body: the flat sibling when present, else the first
    // override file's own body.
    if let Some(flat) = flat_def {
        base.prompt = flat.prompt;
    }
    validate_loaded_def(&base)?;
    Ok(base)
}

fn validate_loaded_def(def: &AgentDef) -> Result<()> {
    validate_invariants(def)?;
    for warning in def.load_warnings() {
        tracing::warn!(agent = %def.name, %warning, "agent definition loaded with warning");
    }
    Ok(())
}

fn read_agent_markdown(path: &Path) -> Result<String> {
    let len = std::fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("statting agent file {}: {e}", path.display()))?
        .len();
    if len > MAX_MARKDOWN_BYTES {
        tracing::warn!(
            path = %path.display(),
            size = len,
            limit = MAX_MARKDOWN_BYTES,
            "skipping oversized agent markdown"
        );
        bail!(
            "agent file {} exceeds {} byte limit",
            path.display(),
            MAX_MARKDOWN_BYTES
        );
    }
    std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading agent file {}: {e}", path.display()))
}

/// Extract the agent name from a path. For the flat-file form that is the
/// file stem (`builder.md` → `builder`); the dir form (`builder/`) — the
/// per-model-slot layout — resolves to the directory name. Centralized so
/// both forms share one name extraction path.
fn agent_name_from_path(path: &Path) -> Option<String> {
    if path.is_dir() {
        return path.file_name().map(|s| s.to_string_lossy().into_owned());
    }
    path.file_stem().map(|s| s.to_string_lossy().into_owned())
}

/// The on-disk agents directory inside a discovered config dir.
fn agents_subdir(config_dir: &Path) -> PathBuf {
    config_dir.join("agents")
}

/// Every directory to search for on-disk agent files, in left-to-right
/// override precedence. Nearest project wins (matching `mcp.json` load
/// layering, most-specific first), then machine-local and home, then
/// configured `extended.agent_dirs`. Unlike skills scan dirs, configured
/// entries are resolved relative to the config file that defined them, not
/// the process cwd and not through ancestor-walk.
pub fn agent_search_dirs(cwd: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = crate::config::dirs::config_dirs_most_specific_first(cwd)
        .into_iter()
        .map(|d| agents_subdir(&d.path))
        .collect();
    dirs.extend(configured_agent_dirs_for_paths(
        &crate::config::dirs::config_file_paths_for_load(cwd),
    ));
    dirs
}

fn configured_agent_dirs_for_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for path in paths {
        if !path.exists() {
            continue;
        }
        let Ok(doc) = crate::config::extended::ExtendedConfigDoc::load(path) else {
            continue;
        };
        let Some(value) = doc.raw_field("agent_dirs") else {
            continue;
        };
        let parsed = match serde_json::from_value::<Vec<PathBuf>>(value.clone()) {
            Ok(parsed) => parsed,
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    key = "agent_dirs",
                    %error,
                    "skipping malformed extended config field"
                );
                continue;
            }
        };
        dirs.extend(
            parsed
                .into_iter()
                .filter_map(|dir| resolve_agent_dir_entry(path, &dir))
                .filter(|dir| !crate::config::trust::path_blocked_by_workspace_trust(dir)),
        );
    }
    dirs
}

fn resolve_agent_dir_entry(config_path: &Path, dir: &Path) -> Option<PathBuf> {
    let rendered = dir.to_string_lossy();
    let resolved = crate::envref::resolve(&rendered);
    if resolved.has_missing() || resolved.has_errors() {
        tracing::warn!(
            path = %config_path.display(),
            key = "agent_dirs",
            missing = ?resolved.missing,
            errors = ?resolved.errors,
            "skipping unresolved agent_dirs entry"
        );
        return None;
    }
    let path = PathBuf::from(resolved.value);
    if path.is_absolute() {
        Some(path)
    } else {
        config_path.parent().map(|parent| parent.join(path))
    }
}

/// Resolve the on-disk path an agent named `name` would resolve to in
/// `dir`, **without** requiring it to exist. The directory form
/// (`<dir>/<name>/`, holding per-model-slot `<key>.md` files) takes
/// precedence when present — it is the richer multi-body source and
/// internally falls back to the flat `<dir>/<name>.md` sibling for any
/// absent slot (implementation note). Otherwise the
/// flat-file form (`<dir>/<name>.md`, the form eject writes) is returned;
/// when neither exists the flat path is returned as the canonical default.
pub fn agent_path_in(dir: &Path, name: &str) -> PathBuf {
    // The directory form wins when it exists.
    let dir_form = dir.join(name);
    if dir_form.is_dir() {
        return dir_form;
    }
    dir.join(format!("{name}.md"))
}

/// Find the first existing on-disk override file for `name`, scanning
/// [`agent_search_dirs`] in precedence order (nearest project first).
/// Returns the path (flat-file or directory package) of the highest-
/// precedence match, or `None` when no override exists (the embedded
/// default applies). A lower-precedence same-named def is logged as
/// shadowed rather than silently winning.
pub fn find_override(cwd: &Path, name: &str) -> Option<PathBuf> {
    let mut found: Option<PathBuf> = None;
    for dir in agent_search_dirs(cwd) {
        let candidate = agent_path_in(&dir, name);
        if !candidate.exists() {
            continue;
        }
        match &found {
            Some(winner) => {
                tracing::warn!(
                    agent = name,
                    winning = %winner.display(),
                    shadowed = %candidate.display(),
                    "project agent definition shadows a lower-precedence definition"
                );
            }
            None => found = Some(candidate),
        }
    }
    found
}

/// Resolve the effective [`AgentDef`] for `name` at `cwd`: the highest-
/// precedence on-disk override if one exists, else the embedded default
/// (for a built-in name). Returns `Ok(None)` when `name` is neither a
/// built-in nor present on disk. A malformed override file fails loudly
/// (naming its `source`) rather than silently falling back to the
/// embedded default — that would hide the user's mistake.
pub fn resolve(cwd: &Path, name: &str) -> Result<Option<AgentDef>> {
    resolve_inner(cwd, name)
}

pub(crate) async fn resolve_with_assistant_db(
    cwd: &Path,
    name: &str,
    db: &crate::db::Db,
) -> Result<Option<AgentDef>> {
    if let Some(def) = resolve_inner(cwd, name)? {
        return Ok(Some(def));
    }
    resolve_assistant_agent_from_db(db, name).await
}

fn resolve_inner(cwd: &Path, name: &str) -> Result<Option<AgentDef>> {
    if is_removed_primary(name) {
        if find_override(cwd, name).is_some() {
            tracing::warn!(
                agent = name,
                "ignoring override for removed builtin primary"
            );
        }
        return Ok(None);
    }
    if let Some(candidate) = find_override(cwd, name) {
        if candidate.is_dir() {
            let dir = candidate
                .parent()
                .context("agent package override has no parent directory")?;
            // Directory form: load every per-model-slot override file present.
            // Built-in packages retain override provenance only after their
            // trusted cockpit/* identity has been checked explicitly.
            return Ok(Some(if is_builtin_agent(name) {
                load_builtin_override_from_dir(dir, name)?
            } else {
                load_from_dir(dir, name, DefinitionScope::Workspace)?
            }));
        }
        if candidate.is_file() {
            return Ok(Some(if is_builtin_agent(name) {
                load_builtin_override_from_file(&candidate, name)?
            } else {
                load_from_file(&candidate)?
            }));
        }
    }
    if let Some(def) = embedded_default(name) {
        return Ok(Some(def));
    }
    Ok(None)
}

async fn resolve_assistant_agent_from_db(
    db: &crate::db::Db,
    name: &str,
) -> Result<Option<AgentDef>> {
    Ok(crate::assistants::load_verified(db, name)
        .await?
        .map(|assistant| assistant.agent))
}

/// Discover every agent visible at `cwd`: each built-in (overridden when
/// an on-disk file exists), plus every custom agent found on disk.
/// Override-by-name means a custom file whose stem collides with a
/// built-in name is folded into that built-in's entry, not listed twice.
/// Malformed files are surfaced as `Err` entries paired with the name so
/// callers (the `/settings` page) can show the problem rather than drop
/// the agent silently.
pub fn list_all(cwd: &Path) -> Vec<AgentListing> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out: Vec<AgentListing> = Vec::new();

    // Built-ins first, in their canonical order, so the list leads with
    // the bundled cast.
    for &name in BUILTIN_AGENT_NAMES {
        let overridden = find_override(cwd, name).is_some();
        let result = resolve(cwd, name).map(|o| o.expect("built-in always resolves"));
        out.push(AgentListing {
            name: name.to_string(),
            kind: AgentKind::Builtin { overridden },
            def: result,
        });
        seen.insert(name.to_string());
    }

    // Then custom agents from disk, de-duplicated across the search path
    // (highest-precedence wins) and skipping built-in names (already
    // folded in above as overrides).
    for dir in agent_search_dirs(cwd) {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = agent_file_candidate_name(&path) else {
                continue;
            };
            if name == PACKAGE_SUBAGENTS_DIR {
                continue;
            }
            if seen.contains(&name) {
                continue;
            }
            if is_removed_primary(&name) {
                tracing::warn!(
                    agent = name,
                    path = %path.display(),
                    "ignoring override for removed builtin primary"
                );
                seen.insert(name);
                continue;
            }
            if agent_markdown_oversized(&path, &dir, &name) {
                continue;
            }
            seen.insert(name.clone());
            let def = if path.is_dir() {
                load_from_dir(&dir, &name, DefinitionScope::Workspace)
            } else {
                load_from_file(&path)
            };
            out.push(AgentListing {
                name,
                kind: AgentKind::Custom,
                def,
            });
        }
    }

    out
}

fn agent_markdown_oversized(path: &Path, dir: &Path, name: &str) -> bool {
    if path.is_dir() {
        return match collect_package_files(path) {
            Ok(_) => false,
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %error,
                    "skipping oversized or unreadable agent package"
                );
                true
            }
        };
    }
    let paths = [path.to_path_buf(), dir.join(format!("{name}.md"))];
    paths.into_iter().any(|p| match std::fs::metadata(&p) {
        Ok(meta) if p.is_file() && meta.len() > MAX_MARKDOWN_BYTES => {
            tracing::warn!(
                path = %p.display(),
                size = meta.len(),
                limit = MAX_MARKDOWN_BYTES,
                "skipping oversized agent markdown"
            );
            true
        }
        _ => false,
    })
}

/// Return the candidate agent name for a dir entry: the stem of a `.md`
/// file, or a directory name (the per-model override form). Non-`.md`
/// files are ignored.
fn agent_file_candidate_name(path: &Path) -> Option<String> {
    if path.is_dir() {
        return path.file_name().map(|s| s.to_string_lossy().into_owned());
    }
    if path.extension().and_then(|e| e.to_str()) == Some("md") {
        return path.file_stem().map(|s| s.to_string_lossy().into_owned());
    }
    None
}

/// One row in the agents listing: a built-in (possibly overridden) or a
/// custom agent, with its parsed definition or the parse error.
pub struct AgentListing {
    pub name: String,
    pub kind: AgentKind,
    pub def: Result<AgentDef>,
}

/// Whether a listed agent is one of the bundled cast or user-authored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentKind {
    /// A built-in agent. `overridden` is true when an on-disk file
    /// shadows its embedded default.
    Builtin { overridden: bool },
    /// A user-authored custom agent (any non-built-in name).
    Custom,
}

/// Eject a built-in agent's embedded default to `<config_dir>/agents/
/// <name>.md` for editing. If an override already exists anywhere on the
/// search path, **do not clobber** it — return its existing path so the
/// caller can open/select it instead. Returns `(path, newly_written)`.
pub fn eject_builtin(cwd: &Path, config_dir: &Path, name: &str) -> Result<(PathBuf, bool)> {
    if !is_builtin_agent(name) {
        bail!("`{name}` is not a built-in agent and cannot be ejected");
    }
    if let Some(existing) = find_override(cwd, name) {
        return Ok((existing, false));
    }
    let def = embedded_default(name).expect("built-in always has an embedded default");
    let dir = agents_subdir(config_dir);
    std::fs::create_dir_all(&dir)
        .map_err(|e| anyhow::anyhow!("creating agents dir {}: {e}", dir.display()))?;
    let path = dir.join(format!("{name}.md"));
    let md = def.to_markdown()?;
    std::fs::write(&path, md)
        .map_err(|e| anyhow::anyhow!("writing agent file {}: {e}", path.display()))?;
    Ok((path, true))
}

/// Reset all built-in agent overrides: delete every on-disk override
/// file for a **built-in** name across the whole search path, restoring
/// the embedded defaults. Custom agents (non-built-in names) are never
/// touched. With no overrides present this is a safe no-op. Returns the
/// paths that were removed.
pub fn reset_all_builtins(cwd: &Path) -> Result<Vec<PathBuf>> {
    let mut removed = Vec::new();
    for dir in agent_search_dirs(cwd) {
        for &name in BUILTIN_AGENT_NAMES {
            let flat = dir.join(format!("{name}.md"));
            if flat.is_file() {
                std::fs::remove_file(&flat)
                    .map_err(|e| anyhow::anyhow!("removing {}: {e}", flat.display()))?;
                removed.push(flat);
            }
            // Per-model override dir form — remove it too so a reset is
            // complete once that form ships.
            let dir_form = dir.join(name);
            if dir_form.is_dir() {
                std::fs::remove_dir_all(&dir_form)
                    .map_err(|e| anyhow::anyhow!("removing {}: {e}", dir_form.display()))?;
                removed.push(dir_form);
            }
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests;
