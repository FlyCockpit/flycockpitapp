//! Loader for the cockpit-only config keys — the former
//! `extended-config.json` superset, now top-level keys in the single
//! per-layer `config.json` (GOALS §2a).
//!
//! Lives alongside layer-wide provider metadata in each discovered `.cockpit/`
//! directory's `config.json` (see `config::dirs`). Schema reference:
//! `the design notes` §4. All fields are optional; a missing file is fine
//! (defaults apply).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub use crate::config::merge::deep_merge_value;

use crate::config::dirs::{ConfigDirKind, config_file_paths_for_load, discover_config_dirs};

mod daemon;
mod data_syntax;
mod delegation;
mod guards;
mod harness;
mod lsp;
mod resource_scheduler;
pub mod tui;

#[allow(unused_imports)]
pub use daemon::{DaemonConfig, DaemonUploadLimitsConfig, RetentionConfig};
#[allow(unused_imports)]
pub use data_syntax::DataSyntaxConfig;
#[allow(unused_imports)]
pub use delegation::{
    DEFAULT_DELEGATION_MAX_PARALLEL, DEFAULT_SWARM_MAX_CONCURRENCY, DEFAULT_SWARM_MAX_DEPTH,
    DeepthinkConfig, DelegationConfig, DelegationRecursionPolicy, ReviewConfig, SwarmConfig,
    persist_review_default_participants,
};
#[allow(unused_imports)]
pub use guards::{
    InjectionResultAction, InjectionThreshold, LoopGuardConfig, MIN_LOOP_GUARD_THRESHOLD,
    PreflightConfig, PromptInjectionGuardConfig, ResolvedInjectionGuard, ResolvedPreflight,
    default_injection_check_prompt, default_preflight_prompt, resolve_injection_guard,
    resolve_preflight,
};
#[allow(unused_imports)]
pub use harness::{
    ArgvOverflowBehavior, DEFAULT_HARNESS_TIMEOUT_SECS, HarnessConfig, PromptInputMode,
    SystemPromptConfig, builtin_harness_presets, resolve_harnesses,
};
#[allow(unused_imports)]
pub use lsp::{
    LspAutoInstall, LspConfig, LspDiagnosticSeverity, LspDiagnosticsConfig, LspServerConfig,
};
#[allow(unused_imports)]
pub use resource_scheduler::{
    DEFAULT_RESOURCE_POOL_CAPACITY, DEFAULT_RESOURCE_SCHEDULER_MAX_QUEUED, ResourcePoolConfig,
    ResourceSchedulerConfig, ResourceSchedulerLimitsConfig, ResourceSchedulerPoolsConfig,
    ResourceSchedulerRuleConfig,
};
#[allow(unused_imports)]
pub use tui::{
    BannerConfig, DiffStyle, SleepScope, ThinkingDisplay, ToolCommandTemplate, TuiConfig,
    VimModeSetting, WebConfig, WebProvider,
};

#[cfg(test)]
use guards::{resolve_injection_guard_from_paths, resolve_preflight_from_paths};
#[cfg(test)]
use harness::resolve_harnesses_from_paths;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedConfig {
    #[serde(default)]
    pub harnesses: HashMap<String, HarnessConfig>,

    /// Ordered list of agent-guidance file names. The first file from this
    /// list that exists in the cwd (or its ancestors up to the git root)
    /// is loaded. Default: `["AGENTS.md", "project guidance"]`.
    #[serde(default = "default_agent_guidance_files")]
    pub agent_guidance_files: Vec<String>,

    /// Concurrency model when an agent fans out: `"subagents"` (in-process)
    /// or `"fork"` (separate cockpit/other-harness subprocess per sub-task).
    #[serde(default)]
    pub concurrency: Concurrency,

    /// Extra directories to search for agent definition files. Paths are
    /// tilde-expanded.
    #[serde(default)]
    pub agent_dirs: Vec<PathBuf>,

    /// Gitignore-style glob patterns that re-permit otherwise-gitignored
    /// paths for the `read`/`readlock` tools and re-include them in the
    /// discovery surfaces (intel index + `@`-tag popup) — the read-allowlist
    /// (implementation note). Project-scoped: writes target
    /// the nearest project `.cockpit/config.json`, and the effective list at
    /// runtime is the union across all active config layers (resolve via
    /// [`resolve_gitignore_allow`]) plus the session set populated by the
    /// approval flow. Default empty (every gitignored path prompts). Always
    /// serialized (even when empty) so clearing the list persists — mirrors
    /// the other editable string-lists (`agent_dirs`, `redact.denylist`).
    #[serde(default)]
    pub gitignore_allow: Vec<String>,

    #[serde(default)]
    pub redact: RedactConfig,

    #[serde(default)]
    pub tui: TuiConfig,

    /// User's display name. When set, the startup logo shows
    /// `Welcome, {name}` between the title line and the provider line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Where the docs agent stores its package snapshots. Tilde-expanded
    /// at read time. Absent means the agent picks its own default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packages_directory: Option<PathBuf>,

    /// User-defined bash-command templates surfaced as built-in tools
    /// (webfetch, websearch, …). Keyed by tool name.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub tools: HashMap<String, ToolCommandTemplate>,

    /// Provider used by the built-in web tools. The shell-template entries in
    /// `tools.webfetch` / `tools.websearch` are consulted only for `custom`.
    #[serde(default, skip_serializing_if = "WebConfig::is_default")]
    pub web: WebConfig,

    /// Require every inference request to use a provider/model marked
    /// `trust: "trusted"`. Off by default.
    #[serde(default, rename = "trustedOnly", alias = "trusted_only")]
    pub trusted_only: bool,

    /// Opt-in to fetching remote `.well-known/cockpit` configs.
    #[serde(default)]
    pub allow_remote_config: bool,

    /// Utility model used for background work that doesn't need the
    /// primary model: session auto-titling (GOALS §17d), the
    /// prompt-injection guard when enabled, and similar small tasks.
    /// Identifier format mirrors the primary model selector
    /// (`"<provider>:<model-id>"`). Unset disables every
    /// utility-model-dependent feature — auto-titling is skipped and
    /// sessions display their short id as the label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utility_model: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub translation_model: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cheap_code: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smart_code: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<String>,

    #[serde(default)]
    pub agent_chooses_subagent_model: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_title: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skill_injection: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predict_next_message_model: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_report_summarization: Option<String>,

    /// Dedicated model for drafting the `/compact` handoff brief
    /// (implementation note). Identifier
    /// format mirrors the primary model selector (`"<provider>:<model-id>"`)
    /// and resolves through the same path as [`Self::utility_model`].
    /// Resolution is exactly two levels: this model when set and non-empty,
    /// else the active agent's own model — it does **not** fall through to
    /// `utility_model`. A configured value that fails to resolve falls back
    /// to the active agent's model (the handoff is never aborted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compact_model: Option<String>,

    /// Full override for the `/compact` handoff-brief instruction
    /// (implementation note). When set and
    /// non-empty it **fully replaces** the default brief prompt text; the
    /// deterministic appendix is unaffected. Unset (or empty after trim)
    /// uses the hardcoded default verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compact_prompt: Option<String>,

    /// Prompt-injection guard config (GOALS §4i). Off by default; v1
    /// scope is user-authored input only.
    #[serde(default)]
    pub prompt_injection_guard: PromptInjectionGuardConfig,

    /// Request-preflight config. Off by default; rewrites a user prompt
    /// through the utility model before it reaches the coding model.
    #[serde(default)]
    pub preflight: PreflightConfig,

    /// System-prompt injection knobs (GOALS §17g, §4k).
    #[serde(default)]
    pub system_prompt: SystemPromptConfig,

    /// Async-schedule subsystem knobs (GOALS §22).
    #[serde(default)]
    pub schedule: ScheduleConfig,

    /// Daemon-owned resource scheduler knobs. The scheduler coordinates
    /// heavyweight work across normal sessions without changing sandboxing or
    /// applying OS-level limits.
    #[serde(rename = "resourceScheduler", default)]
    pub resource_scheduler: ResourceSchedulerConfig,

    /// Shell sandbox substrate configuration. The UI for choosing defaults is
    /// added separately; this engine consumes the Dockerfile path.
    #[serde(default, skip_serializing_if = "SandboxConfig::is_default")]
    pub sandbox: SandboxConfig,

    /// Daemon resource lifecycle limits. These protect daemon-global state
    /// that is shared by every connected client.
    #[serde(default)]
    pub daemon: DaemonConfig,

    /// Session-payload retention knobs.
    #[serde(default)]
    pub retention: RetentionConfig,

    /// Inline delegation-batch knobs. `max_parallel` caps
    /// `task(intent="batch", batch=[...])` fan-out before any child is spawned.
    #[serde(default)]
    pub delegation: DelegationConfig,

    /// Optional deep reasoning leaf subagent. Disabled by default because it
    /// can route prompts to tool-free reasoning models that may be remote or
    /// expensive.
    #[serde(default)]
    pub deepthink: DeepthinkConfig,

    /// `Swarm` recursive-agent knobs (GOALS §24): the depth ceiling +
    /// global concurrency cap on recursive `Swarm` subagents.
    #[serde(default)]
    pub swarm: SwarmConfig,

    /// `/multireview` defaults: participants pre-selected on the next review.
    #[serde(default)]
    pub review: ReviewConfig,

    /// Language Server Protocol diagnostics and navigation settings.
    #[serde(default)]
    pub lsp: LspConfig,

    /// In-process syntax validation notes for standardized data files written
    /// by native write tools.
    #[serde(default)]
    pub data_syntax: DataSyntaxConfig,

    /// Loop-guard knobs: the back-to-back identical tool-call threshold.
    #[serde(default)]
    pub loop_guard: LoopGuardConfig,

    /// Maximum number of primary-agent tool round-trips allowed for one
    /// user message. `0` (default) means unlimited. When nonzero, the
    /// interactive driver pauses after this many `Continue` cycles and asks
    /// whether to grant another chunk; headless runs stop at the ceiling.
    #[serde(rename = "maxPrimaryRounds", default)]
    pub max_primary_rounds: u32,

    /// Answering-dialog knobs (GOALS §3b) — shared by the `question`
    /// tool today and tool-approval prompts later.
    #[serde(default)]
    pub dialog: DialogConfig,

    /// Skills subsystem knobs (GOALS §5): scan directories and the
    /// auto-`!`-command toggle.
    #[serde(default)]
    pub skills: SkillsConfig,

    /// The LLM-strength steering axis. `defensive` (the default) renders
    /// explicit, steering tool/parameter descriptions and selects
    /// `defensive.md` per-mode agent prompts — tuned for the weak-model target
    /// (GOALS §1). `normal` keeps the terse token-economy descriptions and
    /// `normal.md` prompts. `frontier` is the top-tier-model tier: it keeps
    /// terse tool descriptions and selects `frontier.md` prompts when present,
    /// falling back through `normal.md` to the defensive flat body. Distinct
    /// from [`crate::agents::AgentMode`] (`primary`/`subagent`/`all`
    /// reachability) — not auto-inferred from model identity. An unknown value
    /// is rejected with the offending value backticked and the valid set listed.
    #[serde(default, deserialize_with = "deserialize_llm_mode")]
    pub llm_mode: LlmMode,

    /// Which primary agent a new session starts on (the auto-router
    /// feature). `auto` (the default) is the conversational front door that
    /// hands off to `Plan`/`Build`; the user may pin `build` or `plan` to
    /// skip it. `/settings` exposes the cycle; [`initial_active_agent`]
    /// reads this. Distinct from [`crate::agents::AgentMode`] and
    /// [`LlmMode`].
    ///
    /// [`initial_active_agent`]: crate::daemon::session_worker
    #[serde(rename = "defaultPrimaryAgent", default)]
    pub default_primary_agent: DefaultPrimaryAgent,

    /// Round-trip utility-model translation (implementation note).
    /// The user's language and the model's language; when both are set and
    /// differ, the inbound prompt is translated into the model's language
    /// and the agent's final response is translated back into the user's.
    /// Empty/equal languages or an unset utility model disable it.
    #[serde(default)]
    pub translation: TranslationConfig,

    /// Whether sandbox escalation is enabled for new sessions. When true, a
    /// sandboxed command may offer an explicit unsandboxed retry path; the
    /// approval mode still controls whether that retry requires confirmation.
    #[serde(
        default = "default_true",
        rename = "sandbox_escalation_enabled",
        alias = "sandboxEscalationEnabled"
    )]
    pub sandbox_escalation_enabled: bool,

    /// Which command-approval mode new sessions start in
    /// (implementation note). `manual` (the default)
    /// asks the user for every gated call; `auto` runs each gated call past
    /// the utility-model safety gate (safe → run, unsafe → ask); `yolo` runs
    /// everything unprompted. Distinct from the `auto` *router agent*
    /// ([`DefaultPrimaryAgent::Auto`]) and from [`LlmMode`]. `/settings`
    /// exposes the cycle; the session reads this at spawn.
    #[serde(rename = "defaultApprovalMode", default)]
    pub default_approval_mode: ApprovalMode,

    /// Approval risk policy overrides. Defaults are conservative in the
    /// approval layer; this config can cap remembered scopes by risk tier,
    /// program (`"rm"`), or command key (`"gh pr"`).
    #[serde(rename = "approvalPolicy", default)]
    pub approval_policy: ApprovalPolicyConfig,

    /// Composer next-message prediction (implementation note).
    /// After each agent turn the utility model predicts the user's likely
    /// next message and offers it as grey ghost text in an empty composer;
    /// Tab (vim insert mode) accepts it as editable text. `off` issues no
    /// utility call; `short` (the default) bounds the prediction to one
    /// line; `long` allows a bounded full proposed response. `/settings`
    /// exposes the cycle.
    #[serde(rename = "predictNextMessage", default)]
    pub predict_next_message: PredictNextMessage,

    /// Native shell-output compression (implementation note).
    /// When `enabled` (the default) the `bash` tool's stdout/stderr runs
    /// through the natively-reimplemented rtk-style filter (generic noise
    /// strip + per-command strategy) before entering model context, for
    /// token savings (§10). When `disabled` the layer is fully bypassed and
    /// bash output is returned verbatim. Compression is lossy of noise only,
    /// never of signal — errors/warnings/failures/diagnostics always survive
    /// (priority #1). Sits strictly before the §7 redaction chokepoint.
    /// `/settings` exposes the toggle; the session reads this at spawn.
    #[serde(rename = "shellCompression", default)]
    pub shell_compression: ShellCompression,

    /// Command resource-profile opt-ins for wrappers whose own argv does not
    /// reveal the toolchain they drive. Built-in cargo/rustup/rustc commands
    /// are detected directly; this list lets project commands such as
    /// `just test` or `make check` request the same Rust toolchain sandbox
    /// allowlist.
    #[serde(
        rename = "commandResourceProfiles",
        default,
        skip_serializing_if = "CommandResourceProfilesConfig::is_empty"
    )]
    pub command_resource_profiles: CommandResourceProfilesConfig,

    /// Global default for how a leading inline `<think>` block is classified
    /// (implementation note,
    /// implementation note). The lowest tier of
    /// the three-tier resolution (model `inline_think` → provider
    /// `inline_think` → this global); `true` (the default) classifies the
    /// block as THINKING — split into the thinking chip and dropped from later
    /// turns. `false` classifies it as RESPONSE BODY — left inline as ordinary
    /// text (no chip) and carried forward. A provider or model override wins
    /// over this. `/settings` exposes the toggle.
    #[serde(rename = "inlineThink", default = "default_true")]
    pub inline_think: bool,

    /// Global default for surfacing §12 tool-call corrections to the model
    /// (implementation note). The lowest tier of the
    /// three-tier resolution (model `hint_tool_call_corrections` → provider
    /// `hint_tool_call_corrections` → this global); `false` (the default)
    /// keeps today's behavior — a repair silently rewrites the call to
    /// canonical and the user sees a `⟲ repaired` chip, but the model is
    /// never told it erred. `true` additionally prepends a terse
    /// `<repair_note>…</repair_note>` line per fired rule to the wire
    /// tool_result, so a weak ~120k model learns the correction (e.g. that
    /// the field is `path`, not `file_path`) instead of repeating it. A
    /// provider or model override wins over this. `/settings` exposes the
    /// toggle.
    #[serde(rename = "hintToolCallCorrections", default)]
    pub hint_tool_call_corrections: bool,

    /// Global default for recovering a tool call a model emitted as **text**
    /// (a fenced block / bare JSON in the assistant message, structured
    /// `tool_calls` empty) into a real call (implementation note).
    /// The lowest tier of the three-tier resolution (model
    /// `text_embedded_recovery` → provider `text_embedded_recovery` → this
    /// global). `available` (the default) recovers only when the named tool
    /// resolves to a real advertised tool (after fuzzy name-repair); an unknown
    /// tool is surfaced to the user with a yellow warning chip + a model-side
    /// correction nudge, not executed. `strict` always treats a tool-shaped
    /// block as a call attempt — an unknown tool returns a normal `unknown tool`
    /// tool_result fed back to the model. `off` disables recovery (a text-form
    /// call stays plain assistant text). A provider or model override wins over
    /// this. `/settings` exposes the cycle.
    #[serde(rename = "textEmbeddedRecovery", default)]
    pub text_embedded_recovery: TextEmbeddedRecovery,

    /// Call-graph centrality ranking for the `search` and `symbol_find`
    /// intel tools (GOALS §21, prompt `code-graph-centrality-and-context.md`).
    /// `true` (the default) reorders their results by how central the
    /// matched code is in the call graph — an **additive** signal that
    /// never drops or hides a result, so recall is unchanged and only the
    /// order shifts. `false` reverts both tools to their exact unranked
    /// order. Resolved by [`resolve_centrality_ranking`].
    #[serde(rename = "intelCentralityRanking", default = "default_true")]
    pub intel_centrality_ranking: bool,

    /// Experimental-mode gate (implementation note). A
    /// single reusable flag segmenting not-yet-stable features. Off by
    /// default. Its first use gates the `Auto`/`Plan`/`Swarm`/`Build`
    /// builtin primaries (see [`crate::agents::is_experimental_primary`]):
    /// with this off they are fully hidden from the cycle / `/agent` list /
    /// slash swaps and the active primary falls back to `Build`. `/settings`
    /// exposes the toggle.
    #[serde(rename = "experimentalMode", default)]
    pub experimental_mode: bool,
}

/// Whether call-graph centrality ranking is enabled for `cwd` (the
/// `extended.intelCentralityRanking` config gate, default on). Resolved
/// layered — each `config.json` on the walk overlays the previous, so a
/// project layer's setting overrides a home/global one (same precedence
/// as [`resolve_preflight`]). A layer that omits the key leaves the
/// inherited value intact. When off, `search` and `symbol_find` revert to
/// today's exact ordering.
pub fn resolve_centrality_ranking(cwd: &Path) -> bool {
    let paths = config_file_paths_for_load(cwd);
    resolve_centrality_ranking_from_paths(&paths)
}

/// Layering core for [`resolve_centrality_ranking`]: overlay each
/// `config.json` in `paths` (walk order, later/more-specific wins). A
/// layer that omits `intelCentralityRanking` leaves the inherited value
/// intact, distinguished by inspecting the raw JSON. Split out so the
/// project-overrides-home semantics are unit-testable without touching
/// `$HOME`. Default (no layer sets it) is `true`.
fn resolve_centrality_ranking_from_paths(paths: &[PathBuf]) -> bool {
    let mut enabled = true;
    for path in paths {
        if !path.exists() {
            continue;
        }
        let Ok(doc) = ExtendedConfigDoc::load(path) else {
            continue;
        };
        if doc.raw_has_key("intelCentralityRanking") {
            enabled = doc.config().intel_centrality_ranking;
        }
    }
    enabled
}

/// Native shell-output compression mode
/// (implementation note). Governs whether the `bash`
/// tool's output is run through cockpit's rtk-native compression layer
/// before it enters model context.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ShellCompression {
    /// Filter + compress bash output (generic noise strip + per-command
    /// strategy) before context — the default. Token savings; signal
    /// (errors/warnings/failures/diagnostics) is never dropped.
    #[default]
    Enabled,
    /// Bypass the layer entirely — bash output is returned byte-for-byte
    /// (modulo the pre-existing 8 KB head+tail cap and §7 redaction).
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ApprovalPolicyConfig {
    #[serde(default, rename = "riskMaxScope")]
    pub risk_max_scope: HashMap<String, ApprovalPolicyScope>,
    #[serde(default, rename = "programMaxScope")]
    pub program_max_scope: HashMap<String, ApprovalPolicyScope>,
    #[serde(default, rename = "keyMaxScope")]
    pub key_max_scope: HashMap<String, ApprovalPolicyScope>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalPolicyScope {
    Once,
    Session,
    Project,
    Global,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct CommandResourceProfilesConfig {
    /// User-defined declarative command resource profiles. Built-ins are not
    /// represented here; they are supplied by the registry and may be toggled
    /// through `enabled`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profiles: BTreeMap<String, CommandResourceProfileDefinition>,
    /// Approval-key strings for wrapper commands mapped to one or more profile
    /// ids, e.g. `"just ci": ["rust_toolchain", "node_package_manager"]`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub wrappers: BTreeMap<String, Vec<String>>,
    /// Explicit enable/disable bits. Built-in and custom profiles default to
    /// enabled when omitted; unknown future ids are preserved here.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub enabled: BTreeMap<String, bool>,
    /// Forward-compatible fields under `commandResourceProfiles`.
    #[serde(flatten, default, skip_serializing_if = "Map::is_empty")]
    pub extra: Map<String, Value>,
}

impl<'de> Deserialize<'de> for CommandResourceProfilesConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize, Default)]
        struct Raw {
            #[serde(default)]
            profiles: BTreeMap<String, CommandResourceProfileDefinition>,
            #[serde(default)]
            wrappers: BTreeMap<String, Vec<String>>,
            #[serde(default)]
            enabled: BTreeMap<String, bool>,
            #[serde(flatten, default)]
            extra: Map<String, Value>,
        }
        let raw = Raw::deserialize(deserializer)?;
        if raw.extra.contains_key("rustToolchain") {
            return Err(serde::de::Error::custom(
                "commandResourceProfiles.rustToolchain is no longer supported; use commandResourceProfiles.wrappers",
            ));
        }
        Ok(Self {
            profiles: raw.profiles,
            wrappers: raw.wrappers,
            enabled: raw.enabled,
            extra: raw.extra,
        })
    }
}

impl CommandResourceProfilesConfig {
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
            && self.wrappers.is_empty()
            && self.enabled.is_empty()
            && self.extra.is_empty()
    }

    pub fn profile_enabled(&self, id: &str) -> bool {
        self.enabled.get(id).copied().unwrap_or(true)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxConfig {
    #[serde(rename = "defaultMode", default)]
    pub default_mode: crate::config::sandbox_mode::SandboxMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dockerfile: Option<PathBuf>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            default_mode: crate::config::sandbox_mode::SandboxMode::Sandbox,
            dockerfile: None,
        }
    }
}

impl SandboxConfig {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CommandResourceProfileDefinition {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roots: Vec<CommandResourceProfileRoot>,
    #[serde(flatten, default, skip_serializing_if = "Map::is_empty")]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandResourceProfileRoot {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default)]
    pub access: CommandResourceProfileRootAccess,
    #[serde(default, skip_serializing_if = "is_false")]
    pub optional: bool,
    #[serde(rename = "withinCwd", default, skip_serializing_if = "is_false")]
    pub within_cwd: bool,
    #[serde(flatten, default, skip_serializing_if = "Map::is_empty")]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CommandResourceProfileRootAccess {
    Read,
    #[default]
    ReadWrite,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl ShellCompression {
    /// Whether compression is active.
    pub fn is_enabled(self) -> bool {
        matches!(self, ShellCompression::Enabled)
    }

    /// Flip between the two values — the `/settings` row's toggle action.
    pub fn toggled(self) -> Self {
        match self {
            ShellCompression::Enabled => ShellCompression::Disabled,
            ShellCompression::Disabled => ShellCompression::Enabled,
        }
    }
}

/// Composer next-message prediction mode (implementation note).
/// Governs whether — and how long — the utility-model prediction shown as
/// composer ghost text may be.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum PredictNextMessage {
    /// No prediction: no utility call, no ghost text.
    Off,
    /// Bounded to a single line (the default).
    #[default]
    Short,
    /// A bounded full proposed response (may be multi-line).
    Long,
}

impl PredictNextMessage {
    /// Whether prediction is enabled (any non-`off` mode).
    pub fn is_enabled(self) -> bool {
        !matches!(self, PredictNextMessage::Off)
    }

    /// Cycle to the next choice — the `/settings` row's toggle action
    /// (`off → short → long → off`).
    pub fn cycled(self) -> Self {
        match self {
            PredictNextMessage::Off => PredictNextMessage::Short,
            PredictNextMessage::Short => PredictNextMessage::Long,
            PredictNextMessage::Long => PredictNextMessage::Off,
        }
    }
}

/// Whether — and how strictly — a tool call a model emitted as **text** (a
/// fenced block / bare JSON in the assistant message, with the structured
/// `tool_calls` field empty) is recovered into a real call
/// (implementation note). A priority-#1 "defensive against weak
/// models" knob: gemma-class models routinely emit calls only as text.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TextEmbeddedRecovery {
    /// Recover a qualifying block ONLY when the named tool resolves (after
    /// fuzzy name-repair) to a tool that actually exists in this turn's
    /// advertised set. An unresolved name is surfaced to the user with a yellow
    /// warning chip + a model-side correction nudge — not executed, not a hard
    /// failure. The default.
    #[default]
    Available,
    /// Always treat a qualifying tool-shaped block as a call attempt. A
    /// resolved name dispatches; an unresolved name returns a normal
    /// `unknown tool X` tool_result fed back to the model, keeping it in the
    /// tool loop.
    Strict,
    /// No recovery — a text-form call stays plain assistant text (today's
    /// behavior).
    Off,
}

impl TextEmbeddedRecovery {
    /// Cycle to the next choice — the `/settings` row's toggle action
    /// (`available → strict → off → available`).
    pub fn cycled(self) -> Self {
        match self {
            TextEmbeddedRecovery::Available => TextEmbeddedRecovery::Strict,
            TextEmbeddedRecovery::Strict => TextEmbeddedRecovery::Off,
            TextEmbeddedRecovery::Off => TextEmbeddedRecovery::Available,
        }
    }
}

/// Round-trip translation config (implementation note). Both
/// languages are free-text labels handed verbatim to the utility model
/// (e.g. `"Spanish"`, `"English"`, `"日本語"`); the comparison that decides
/// whether to translate is trim + case-insensitive, and an empty value on
/// either side disables the feature. Names rather than ISO codes so the
/// utility model gets the most natural instruction.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TranslationConfig {
    /// The user's language (inbound source / outbound target). Empty
    /// disables translation.
    #[serde(default)]
    pub user_language: String,
    /// The model's language (inbound target / outbound source). Empty
    /// disables translation.
    #[serde(default)]
    pub model_language: String,
}

impl TranslationConfig {
    /// Whether round-trip translation is active: both languages are
    /// non-empty (after trimming) and differ case-insensitively. When this
    /// is false, text flows through untranslated.
    pub fn is_active(&self) -> bool {
        let user = self.user_language.trim();
        let model = self.model_language.trim();
        !user.is_empty() && !model.is_empty() && !user.eq_ignore_ascii_case(model)
    }
}

/// Which primary agent a new session starts on (the auto-router feature).
/// The serde spelling is lowercase (`auto`/`build`/`plan`); the resolved
/// agent name [`Self::agent_name`] keeps the in-binary casing convention
/// (capitalized primaries — `Auto`/`Build`/`Plan`).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DefaultPrimaryAgent {
    /// The conversational front door (default): routes to `Plan`/`Build`.
    #[default]
    Auto,
    /// Start directly on `Build` (make-the-change-now).
    Build,
    /// Start directly on `Plan` for plan-mode deliberation.
    Plan,
}

impl DefaultPrimaryAgent {
    /// The in-binary agent name (the capitalized primary spelling the
    /// agent factory + `swap_primary` match on).
    pub fn agent_name(self) -> &'static str {
        match self {
            DefaultPrimaryAgent::Auto => "Auto",
            DefaultPrimaryAgent::Build => "Build",
            DefaultPrimaryAgent::Plan => "Plan",
        }
    }

    /// Cycle to the next choice — the `/settings` row's toggle action.
    pub fn cycled(self) -> Self {
        match self {
            DefaultPrimaryAgent::Auto => DefaultPrimaryAgent::Build,
            DefaultPrimaryAgent::Build => DefaultPrimaryAgent::Plan,
            DefaultPrimaryAgent::Plan => DefaultPrimaryAgent::Auto,
        }
    }
}

/// Command-approval mode (implementation note).
/// Governs whether — and how — a gated tool call (`bash`, `webfetch`, `mcp`)
/// prompts the user before it runs.
///
/// Deliberately distinct from the `auto`/`Auto` *router agent*
/// ([`DefaultPrimaryAgent::Auto`]) and from [`LlmMode`]: this is the
/// *approval* `auto`, the safety-gate engine. UI labels disambiguate it as
/// "auto (safety-gated)" so the two are never conflated.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalMode {
    /// Ask the user for every gated call (the default — the safety gate is
    /// not invoked; the user is the gate).
    #[default]
    Manual,
    /// Route each gated call past the utility-model safety gate first: a
    /// `safe` verdict runs without prompting, an `unsafe` one escalates to
    /// the user. Fails closed (asks the user) when the utility model is
    /// unset/unavailable.
    Auto,
    /// Run every gated call unprompted (the safety gate is bypassed).
    Yolo,
}

impl ApprovalMode {
    /// The lowercase config/serde spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            ApprovalMode::Manual => "manual",
            ApprovalMode::Auto => "auto",
            ApprovalMode::Yolo => "yolo",
        }
    }

    /// Cycle to the next choice — the `/settings` row's toggle action
    /// (`manual` → `auto` → `yolo` → `manual`).
    pub fn cycled(self) -> Self {
        match self {
            ApprovalMode::Manual => ApprovalMode::Auto,
            ApprovalMode::Auto => ApprovalMode::Yolo,
            ApprovalMode::Yolo => ApprovalMode::Manual,
        }
    }
}

/// The LLM-strength steering axis.
/// The only thing called a *mode* in cockpit's agent surface; `Plan` and
/// `Build` are agents, not modes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "lowercase")]
pub enum LlmMode {
    /// Cheaper/weaker ~120k-context models (the default, GOALS §1 target):
    /// explicit steering descriptions, `defensive.md` prompts, interactive-
    /// subagent decomposition.
    #[default]
    Defensive,
    /// Middle/default strong-model tier: terse descriptions, `normal.md`
    /// prompts, and existing non-defensive behavior.
    Normal,
    /// Top-tier models: terse descriptions, optional `frontier.md` prompts,
    /// and high-autonomy policy hooks for later prompts.
    Frontier,
}

impl LlmMode {
    /// The on-disk per-mode agent-prompt file name (`<name>/<mode>.md`).
    pub fn prompt_file(self) -> &'static str {
        match self {
            LlmMode::Defensive => "defensive.md",
            LlmMode::Normal => "normal.md",
            LlmMode::Frontier => "frontier.md",
        }
    }

    /// The lowercase config/serde spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            LlmMode::Defensive => "defensive",
            LlmMode::Normal => "normal",
            LlmMode::Frontier => "frontier",
        }
    }

    /// Cycle through the values — the `/llm-mode toggle` action.
    pub fn cycled(self) -> Self {
        match self {
            LlmMode::Defensive => LlmMode::Normal,
            LlmMode::Normal => LlmMode::Frontier,
            LlmMode::Frontier => LlmMode::Defensive,
        }
    }
}

/// Reject an unknown `llm_mode` with the offending value backticked and
/// the valid set listed — mirrors [`deserialize_vim_mode_setting`]'s
/// error style.
fn deserialize_llm_mode<'de, D>(d: D) -> Result<LlmMode, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let v = serde_json::Value::deserialize(d)?;
    match v {
        serde_json::Value::Null => Ok(LlmMode::default()),
        serde_json::Value::String(s) => match s.as_str() {
            "defensive" => Ok(LlmMode::Defensive),
            "normal" => Ok(LlmMode::Normal),
            "frontier" => Ok(LlmMode::Frontier),
            other => Err(D::Error::custom(format!(
                "unknown llm_mode `{other}` (expected defensive|normal|frontier)"
            ))),
        },
        _ => Err(D::Error::custom("llm_mode must be a string")),
    }
}

pub const SEEDED_SCAN_DIRS: [&str; 2] = ["~/.agents/skills", "./.agents/skills"];

/// Skills subsystem config (GOALS §5).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SkillsConfig {
    /// Directories scanned for `<name>/SKILL.md`. Each entry supports `~`
    /// home expansion, `$VAR` references, and relative paths resolved
    /// against cwd. The list ships pre-seeded on a fresh install with
    /// [`SEEDED_SCAN_DIRS`] (`~/.agents/skills` + `./.agents/skills`) as
    /// ordinary editable rows; an empty list scans **nothing** — there
    /// is no implicit "empty = defaults" fallback. Relative entries
    /// resolve against cwd, or against cwd plus every ancestor up to the
    /// git worktree root when [`Self::ancestor_walk`] is enabled.
    #[serde(default)]
    pub scan_dirs: Vec<String>,

    /// Auto-`!`-command toggle. `true` = Claude mode (inline
    /// `` !`command` `` directives in a skill body run, their stdout
    /// replaces the directive — scrubbed before entering context).
    /// `false` (default) = Codex mode (directives injected verbatim; the
    /// command never runs). Default disabled: auto-running shell is a
    /// footgun; correctness/safety over convenience.
    #[serde(default)]
    pub auto_bang_commands: bool,

    /// Ancestor-walk toggle for **relative** scan-dir entries. `false`
    /// (default): a relative entry resolves against cwd only. `true`:
    /// each relative entry expands at resolve time to cwd **plus** every
    /// ancestor directory up to and including the git worktree root, so a
    /// repo-root `./.agents/skills` is found from any subdirectory.
    /// Absolute / `~` / `$VAR`-rooted entries are unaffected.
    #[serde(default)]
    pub ancestor_walk: bool,
}

impl SkillsConfig {
    /// The fresh-install default a user sees on a brand-new install: the
    /// [`SEEDED_SCAN_DIRS`] materialized as editable rows, everything else
    /// at its derived default (ancestor-walk off, Codex mode). This is the
    /// target a `/settings → Skills` page-level reset restores to — it
    /// matches what [`load_for_cwd`] seeds, so reset and fresh install
    /// agree rather than diverging to the empty derived `Default`.
    pub fn seeded_default() -> Self {
        Self {
            scan_dirs: SEEDED_SCAN_DIRS.iter().map(|s| s.to_string()).collect(),
            ..Self::default()
        }
    }
}

/// Answering-dialog config (GOALS §3b). Governs the reusable selectable-
/// pages dialog that the `question` tool — and, later, tool-approval
/// prompts — present over the composer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DialogConfig {
    /// Anti-misfire lockout: how long (milliseconds) the dialog ignores
    /// input after it appears, so a user who was mid-typing in the
    /// composer can't accidentally answer. The border renders grey
    /// during the lockout and white once it elapses. Default 1500 ms.
    #[serde(default = "default_dialog_lockout_ms")]
    pub lockout_ms: u64,
}

impl Default for DialogConfig {
    fn default() -> Self {
        Self {
            lockout_ms: default_dialog_lockout_ms(),
        }
    }
}

default_const!(default_dialog_lockout_ms, u64, 1500);

/// Async-schedule subsystem config (GOALS §22).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleConfig {
    /// Cap on concurrently-running scheduled tasks per session. Guards against
    /// accidental fan-out (the fork-can't-spawn rule prevents recursion).
    #[serde(default = "default_max_concurrent_schedules")]
    pub max_concurrent: usize,
    /// Allow schedule `limit = 0` loops to ask for a one-time per-session
    /// interactive approval. Default false: unbounded loops are rejected.
    #[serde(
        rename = "allowUnboundedLoops",
        alias = "allow_unbounded_loops",
        default
    )]
    pub allow_unbounded_loops: bool,
}

impl Default for ScheduleConfig {
    fn default() -> Self {
        Self {
            max_concurrent: default_max_concurrent_schedules(),
            allow_unbounded_loops: false,
        }
    }
}

pub const DEFAULT_MAX_CONCURRENT_SCHEDULES: usize = 8;

default_const!(
    default_max_concurrent_schedules,
    usize,
    DEFAULT_MAX_CONCURRENT_SCHEDULES
);

/// Resolve the effective `gitignore_allow` list for `cwd`: the **union** of
/// every active config layer's `gitignore_allow` field, in walk order
/// (least- to most-specific), de-duplicated while preserving first-seen
/// order. Mirrors how other list-valued config (skills `scan_dirs`,
/// `agent_dirs`) is gathered across layers — a plain union, not the generic
/// merge engine. The read-allowlist gate unions this with the session set.
pub fn resolve_gitignore_allow(cwd: &Path) -> Vec<String> {
    let paths = config_file_paths_for_load(cwd);
    resolve_gitignore_allow_from_paths(&paths)
}

/// Layering core for [`resolve_gitignore_allow`], split out so the union
/// semantics are unit-testable without touching `$HOME`. `paths` is in walk
/// order; each existing/parseable layer contributes its `gitignore_allow`
/// entries, de-duplicated in first-seen order.
fn resolve_gitignore_allow_from_paths(paths: &[PathBuf]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for path in paths {
        if !path.exists() {
            continue;
        }
        let Ok(doc) = ExtendedConfigDoc::load(path) else {
            continue;
        };
        for glob in doc.config().gitignore_allow {
            let glob = glob.trim().to_string();
            if !glob.is_empty() && !out.contains(&glob) {
                out.push(glob);
            }
        }
    }
    out
}

#[derive(Debug, Default, PartialEq, Eq)]
struct RedactListUnions {
    denylist: Vec<String>,
    allowlist: Vec<String>,
    extra_dotenv_paths: Vec<PathBuf>,
}

/// Resolve the security-sensitive list-valued redaction fields as a
/// de-duplicated union across config layers. The generic deep-merge engine
/// replaces arrays; these three fields are explicitly concat/union per GOALS
/// §2b, mirroring the dedicated `gitignore_allow` override path.
fn resolve_redact_list_unions_from_paths(paths: &[PathBuf]) -> RedactListUnions {
    let mut out = RedactListUnions::default();
    let mut denylist_seen: HashSet<String> = HashSet::new();
    let mut allowlist_seen: HashSet<String> = HashSet::new();
    let mut extra_dotenv_paths_seen: HashSet<PathBuf> = HashSet::new();

    for path in paths {
        if !path.exists() {
            continue;
        }
        let Ok(doc) = ExtendedConfigDoc::load(path) else {
            continue;
        };
        let Some(redact) = doc.raw.get("redact").and_then(Value::as_object) else {
            continue;
        };
        let denylist = redact_list_strings(redact, "denylist");
        let allowlist = redact_list_strings(redact, "allowlist");
        let extra_dotenv_paths = redact_list_paths(redact, "extra_dotenv_paths");

        for value in denylist {
            let value = value.trim().to_string();
            if !value.is_empty() && denylist_seen.insert(value.clone()) {
                out.denylist.push(value);
            }
        }
        for value in allowlist {
            let value = value.trim().to_string();
            if !value.is_empty() && allowlist_seen.insert(value.clone()) {
                out.allowlist.push(value);
            }
        }
        for path in extra_dotenv_paths {
            if path.to_string_lossy().trim().is_empty() {
                continue;
            }
            if extra_dotenv_paths_seen.insert(path.clone()) {
                out.extra_dotenv_paths.push(path);
            }
        }
    }

    out
}

fn redact_list_strings(redact: &Map<String, Value>, key: &str) -> Vec<String> {
    redact
        .get(key)
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_default()
}

fn redact_list_paths(redact: &Map<String, Value>, key: &str) -> Vec<PathBuf> {
    redact
        .get(key)
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_default()
}

/// Append `glob` to the `gitignore_allow` list in the **nearest project**
/// `.cockpit/config.json` (implementation note,
/// "Approve for this project"). The target is the deepest ancestor of `cwd`
/// that already holds a `.cockpit/` project layer; when none exists, a
/// `.cockpit/config.json` is scaffolded at `cwd`. A duplicate glob is a no-op.
/// Round-trips through [`ExtendedConfigDoc`] so sibling layer/provider metadata
/// (and any unknown keys) are preserved.
pub fn append_gitignore_allow_to_project(cwd: &Path, glob: &str) -> Result<()> {
    let glob = glob.trim();
    if glob.is_empty() {
        return Ok(());
    }
    let path = nearest_project_config_path(cwd);
    let mut doc = ExtendedConfigDoc::load(&path)?;
    let mut cfg = doc.config();
    if !cfg.gitignore_allow.iter().any(|g| g == glob) {
        cfg.gitignore_allow.push(glob.to_string());
    }
    doc.write(&cfg)?;
    Ok(())
}

fn nearest_project_config_path(cwd: &Path) -> PathBuf {
    use crate::config::dirs::CONFIG_FILE;
    let project_dir = discover_config_dirs(cwd)
        .into_iter()
        .find(|d| d.kind == ConfigDirKind::Project)
        .map(|d| d.path)
        .unwrap_or_else(|| cwd.join(".cockpit"));
    project_dir.join(CONFIG_FILE)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Concurrency {
    #[default]
    Subagents,
    Fork,
}

/// Default env-file match patterns (gitignore syntax): `.env` and
/// `.env.local`, matched cwd-downward through subdirectories (§7).
pub fn default_dotenv_patterns() -> Vec<String> {
    vec![".env".to_string(), ".env.local".to_string()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RedactConfig {
    pub enabled: bool,
    pub scan_environment: bool,
    pub scan_dotenv: bool,
    /// Scan the user's SSH directory and add every **private** key file's
    /// contents to the redaction table as a forced (non-prunable) secret, so
    /// a private key echoed into a tool result is scrubbed. Default ON when
    /// redaction is enabled. Public keys (`*.pub`) are never registered
    /// (content-based PEM-header detection). See `redact::mod`.
    #[serde(default = "default_true")]
    pub scan_ssh_keys: bool,
    /// Directory scanned for private SSH keys when `scan_ssh_keys` is on.
    /// `None` (default) resolves to the user's `~/.ssh` cross-platform
    /// (`%USERPROFILE%\.ssh` on Windows, via `dirs::home_dir()`).
    #[serde(default)]
    pub ssh_key_dir: Option<PathBuf>,
    /// Gitignore-style globs (default `[".env", ".env.local"]`) matched
    /// **cwd-downward** through subdirectories to discover env files to
    /// scan (§7). Replaces the old walk-up-to-git-root discovery.
    #[serde(default = "default_dotenv_patterns")]
    pub dotenv_patterns: Vec<String>,
    #[serde(default)]
    pub extra_dotenv_paths: Vec<PathBuf>,
    pub min_secret_length: usize,
    pub placeholder: String,
    /// User-supplied literal values that must *always* be redacted, even
    /// if shorter than `min_secret_length` or sourced from an
    /// allowlisted env var. Per spec §2b merging.
    #[serde(default)]
    pub denylist: Vec<String>,
    /// User-supplied env var names to *exclude* from the redaction
    /// table on top of the built-in `ENV_ALLOWLIST` in `redact::mod`.
    #[serde(default)]
    pub allowlist: Vec<String>,
}

impl Default for RedactConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_environment: true,
            scan_dotenv: true,
            scan_ssh_keys: true,
            ssh_key_dir: None,
            dotenv_patterns: default_dotenv_patterns(),
            extra_dotenv_paths: vec![],
            min_secret_length: 8,
            placeholder: "**REDACTED BY COCKPIT - DO NOT TRY TO OBTAIN BY WORKAROUND**".to_string(),
            denylist: vec![],
            allowlist: vec![],
        }
    }
}

default_const!(default_true, bool, true);

impl ExtendedConfig {
    /// The model ref for utility-model guard work: the injection guard's
    /// own override, else the shared `utility_model`.
    pub fn guard_model_ref(&self) -> Option<&str> {
        self.prompt_injection_guard
            .model
            .as_deref()
            .or(self.utility_model.as_deref())
    }

    /// The model ref for request-preflight work: the preflight config's
    /// own override, else the shared `utility_model`. Mirrors
    /// [`Self::guard_model_ref`].
    pub fn preflight_model_ref(&self) -> Option<&str> {
        self.preflight
            .model
            .as_deref()
            .or(self.utility_model.as_deref())
    }

    pub fn auto_title_model_ref(&self) -> Option<&str> {
        self.auto_title.as_deref().or(self.utility_model.as_deref())
    }

    pub fn skill_injection_model_ref(&self) -> Option<&str> {
        self.skill_injection
            .as_deref()
            .or(self.utility_model.as_deref())
    }

    pub fn predict_next_message_model_ref(&self) -> Option<&str> {
        self.predict_next_message_model
            .as_deref()
            .or(self.utility_model.as_deref())
    }

    #[allow(dead_code)]
    pub fn harness_report_summarization_model_ref(&self) -> Option<&str> {
        self.harness_report_summarization
            .as_deref()
            .or(self.utility_model.as_deref())
    }

    pub fn translation_model_ref(&self) -> Option<&str> {
        self.translation_model
            .as_deref()
            .or(self.utility_model.as_deref())
    }

    /// The model ref for drafting the `/compact` handoff brief: the
    /// dedicated `compact_model` when set and non-empty (after trimming),
    /// else the shared `utility_model`. An unset/empty result means "use
    /// the active agent's model".
    pub fn compact_model_ref(&self) -> Option<&str> {
        self.compact_model
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or(self.utility_model.as_deref())
    }
}

impl Default for ExtendedConfig {
    fn default() -> Self {
        Self {
            harnesses: HashMap::new(),
            agent_guidance_files: default_agent_guidance_files(),
            concurrency: Concurrency::default(),
            agent_dirs: Vec::new(),
            gitignore_allow: Vec::new(),
            redact: RedactConfig::default(),
            tui: TuiConfig::default(),
            name: None,
            packages_directory: None,
            tools: HashMap::new(),
            web: WebConfig::default(),
            trusted_only: false,
            allow_remote_config: false,
            utility_model: None,
            translation_model: None,
            cheap_code: None,
            smart_code: None,
            reasoning: None,
            agent_chooses_subagent_model: false,
            auto_title: None,
            skill_injection: None,
            predict_next_message_model: None,
            harness_report_summarization: None,
            compact_model: None,
            compact_prompt: None,
            prompt_injection_guard: PromptInjectionGuardConfig::default(),
            preflight: PreflightConfig::default(),
            system_prompt: SystemPromptConfig::default(),
            schedule: ScheduleConfig::default(),
            resource_scheduler: ResourceSchedulerConfig::default(),
            sandbox: SandboxConfig::default(),
            daemon: DaemonConfig::default(),
            retention: RetentionConfig::default(),
            delegation: DelegationConfig::default(),
            deepthink: DeepthinkConfig::default(),
            swarm: SwarmConfig::default(),
            review: ReviewConfig::default(),
            lsp: LspConfig::default(),
            data_syntax: DataSyntaxConfig::default(),
            loop_guard: LoopGuardConfig::default(),
            max_primary_rounds: 0,
            dialog: DialogConfig::default(),
            skills: SkillsConfig::default(),
            llm_mode: LlmMode::default(),
            default_primary_agent: DefaultPrimaryAgent::default(),
            translation: TranslationConfig::default(),
            sandbox_escalation_enabled: true,
            default_approval_mode: ApprovalMode::default(),
            approval_policy: ApprovalPolicyConfig::default(),
            predict_next_message: PredictNextMessage::default(),
            shell_compression: ShellCompression::default(),
            command_resource_profiles: CommandResourceProfilesConfig::default(),
            inline_think: default_true(),
            hint_tool_call_corrections: false,
            text_embedded_recovery: TextEmbeddedRecovery::default(),
            intel_centrality_ranking: default_true(),
            experimental_mode: false,
        }
    }
}

fn default_agent_guidance_files() -> Vec<String> {
    vec!["AGENTS.md".into()]
}

thread_local! {
    static LOAD_FOR_CWD_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub fn reset_load_for_cwd_call_count() {
    LOAD_FOR_CWD_CALLS.with(|calls| calls.set(0));
}

pub fn load_for_cwd_call_count() -> usize {
    LOAD_FOR_CWD_CALLS.with(std::cell::Cell::get)
}

/// Load the effective [`ExtendedConfig`] for `cwd`: all existing
/// `config.json` layers are merged from least-specific to most-specific, or —
/// when **none** exists anywhere (a genuinely *fresh install*) — `Default` with
/// the skills scan-dir list seeded to [`SEEDED_SCAN_DIRS`]. `COCKPIT_CONFIG`
/// bypasses discovery and supplies the only `config.json` layer.
///
/// The fresh-install distinction is made here, at the *file-existence*
/// level: an absent file and an existing empty `{}` both parse to an
/// empty `scan_dirs`, so they can't be told apart after parse. The
/// seeding is materialization-only — it never happens for an existing
/// on-disk config whose `scan_dirs` is absent/empty (clean break: scan
/// nothing).
pub fn load_for_cwd(cwd: &Path) -> ExtendedConfig {
    LOAD_FOR_CWD_CALLS.with(|calls| calls.set(calls.get() + 1));
    let paths = config_file_paths_for_load(cwd);
    if let Some(mut cfg) = load_merged_from_paths(&paths) {
        cfg.gitignore_allow = resolve_gitignore_allow_from_paths(&paths);
        let redact_unions = resolve_redact_list_unions_from_paths(&paths);
        cfg.redact.denylist = redact_unions.denylist;
        cfg.redact.allowlist = redact_unions.allowlist;
        cfg.redact.extra_dotenv_paths = redact_unions.extra_dotenv_paths;
        return cfg;
    }
    // Fresh install: no config on disk. Materialize the seeded
    // skills scan-dirs so new users discover (and see in `/settings`) the
    // default skill directories.
    ExtendedConfig {
        skills: SkillsConfig::seeded_default(),
        ..Default::default()
    }
}

fn load_merged_from_paths(paths: &[PathBuf]) -> Option<ExtendedConfig> {
    let mut merged =
        serde_json::to_value(ExtendedConfig::default()).unwrap_or(Value::Object(Map::new()));
    let mut saw_existing = false;
    for path in paths {
        if !path.exists() {
            continue;
        }
        match ExtendedConfigDoc::load(path) {
            Ok(doc) => {
                saw_existing = true;
                let layer = doc.raw_for_layer_merge();
                deep_merge_value(&mut merged, &layer);
            }
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "skipping malformed config layer");
            }
        }
    }
    saw_existing.then(|| {
        ExtendedConfigDoc {
            path: PathBuf::from("<merged effective config>"),
            raw: merged,
        }
        .config()
    })
}

/// Round-trip loader/saver for the cockpit-only keys in `config.json` that
/// preserves unknown fields. Same pattern as
/// [`crate::config::providers::ConfigDoc`] (which owns layer-wide provider
/// metadata in the same file): the raw `Value` is held alongside the typed view
/// so a write only overwrites the keys it models and never destroys the
/// sibling layer/provider metadata (or fields a future cockpit version added).
pub struct ExtendedConfigDoc {
    pub path: PathBuf,
    raw: Value,
}

impl ExtendedConfigDoc {
    pub fn load(path: &Path) -> Result<Self> {
        let raw_str = if path.exists() {
            std::fs::read_to_string(path)
                .with_context(|| format!("reading config.json at {}", path.display()))?
        } else {
            "{}".to_string()
        };
        let raw: Value = if raw_str.trim().is_empty() {
            Value::Object(Map::new())
        } else {
            serde_json::from_str(&raw_str)
                .with_context(|| format!("parsing config.json at {}", path.display()))?
        };
        let raw = match raw {
            Value::Object(_) => raw,
            other => {
                anyhow::bail!("expected config.json root to be an object, found {other:?}")
            }
        };
        Ok(Self {
            path: path.to_path_buf(),
            raw,
        })
    }

    /// Parse the raw object into the typed [`ExtendedConfig`]. Each known
    /// top-level field is decoded independently so a malformed unrelated
    /// field cannot zero the entire settings view.
    pub fn config(&self) -> ExtendedConfig {
        self.config_with_warnings().0
    }

    pub fn raw_field(&self, key: &str) -> Option<&Value> {
        self.raw.get(key)
    }

    /// Parse the raw object and return human-readable warnings for known
    /// fields that were malformed and therefore left at their defaults.
    pub fn config_with_warnings(&self) -> (ExtendedConfig, Vec<String>) {
        let mut cfg = ExtendedConfig::default();
        let mut warnings = Vec::new();
        let Some(raw) = self.raw.as_object() else {
            return (cfg, warnings);
        };

        macro_rules! parse_field {
            ($key:literal, $field:ident) => {
                if let Some(value) = raw.get($key) {
                    match serde_json::from_value(value.clone()) {
                        Ok(parsed) => cfg.$field = parsed,
                        Err(error) => {
                            tracing::warn!(
                                path = %self.path.display(),
                                key = $key,
                                %error,
                                "skipping malformed extended config field"
                            );
                            warnings.push(format!("ignored malformed `{}` in {}", $key, self.path.display()));
                        }
                    }
                }
            };
        }

        parse_field!("harnesses", harnesses);
        parse_field!("agent_guidance_files", agent_guidance_files);
        parse_field!("concurrency", concurrency);
        parse_field!("agent_dirs", agent_dirs);
        parse_field!("gitignore_allow", gitignore_allow);
        parse_field!("redact", redact);
        parse_field!("tui", tui);
        parse_field!("name", name);
        parse_field!("packages_directory", packages_directory);
        parse_field!("tools", tools);
        parse_field!("web", web);
        parse_field!("trustedOnly", trusted_only);
        parse_field!("trusted_only", trusted_only);
        parse_field!("allow_remote_config", allow_remote_config);
        parse_field!("utility_model", utility_model);
        parse_field!("translation_model", translation_model);
        parse_field!("cheap_code", cheap_code);
        parse_field!("smart_code", smart_code);
        parse_field!("reasoning", reasoning);
        parse_field!("agent_chooses_subagent_model", agent_chooses_subagent_model);
        parse_field!("auto_title", auto_title);
        parse_field!("skill_injection", skill_injection);
        parse_field!("predict_next_message_model", predict_next_message_model);
        parse_field!("harness_report_summarization", harness_report_summarization);
        parse_field!("compact_model", compact_model);
        parse_field!("compact_prompt", compact_prompt);
        parse_field!("prompt_injection_guard", prompt_injection_guard);
        parse_field!("preflight", preflight);
        parse_field!("system_prompt", system_prompt);
        parse_field!("schedule", schedule);
        parse_field!("resourceScheduler", resource_scheduler);
        parse_field!("sandbox", sandbox);
        parse_field!("delegation", delegation);
        parse_field!("deepthink", deepthink);
        parse_field!("swarm", swarm);
        parse_field!("review", review);
        parse_field!("lsp", lsp);
        parse_field!("data_syntax", data_syntax);
        parse_field!("loop_guard", loop_guard);
        parse_field!("maxPrimaryRounds", max_primary_rounds);
        parse_field!("dialog", dialog);
        parse_field!("skills", skills);
        parse_field!("llm_mode", llm_mode);
        parse_field!("defaultPrimaryAgent", default_primary_agent);
        parse_field!("translation", translation);
        parse_field!("sandboxEscalationEnabled", sandbox_escalation_enabled);
        parse_field!("sandbox_escalation_enabled", sandbox_escalation_enabled);
        parse_field!("defaultApprovalMode", default_approval_mode);
        parse_field!("approvalPolicy", approval_policy);
        parse_field!("predictNextMessage", predict_next_message);
        parse_field!("shellCompression", shell_compression);
        parse_field!("commandResourceProfiles", command_resource_profiles);
        parse_field!("inlineThink", inline_think);
        parse_field!("hintToolCallCorrections", hint_tool_call_corrections);
        parse_field!("textEmbeddedRecovery", text_embedded_recovery);
        parse_field!("intelCentralityRanking", intel_centrality_ranking);
        parse_field!("experimentalMode", experimental_mode);

        (cfg, warnings)
    }

    fn raw_for_layer_merge(&self) -> Value {
        let mut raw = self.raw.clone();
        let Some(obj) = raw.as_object_mut() else {
            return raw;
        };

        macro_rules! remove_malformed {
            ($key:literal, $ty:ty) => {
                if let Some(value) = obj.get($key)
                    && let Err(error) = serde_json::from_value::<$ty>(value.clone())
                {
                    tracing::warn!(
                        path = %self.path.display(),
                        key = $key,
                        %error,
                        "skipping malformed extended config field in layer merge"
                    );
                    obj.remove($key);
                }
            };
        }

        remove_malformed!("redact", RedactConfig);
        remove_malformed!("tui", TuiConfig);
        remove_malformed!("trustedOnly", bool);
        remove_malformed!("trusted_only", bool);
        remove_malformed!("sandboxEscalationEnabled", bool);
        remove_malformed!("sandbox_escalation_enabled", bool);
        remove_malformed!("prompt_injection_guard", PromptInjectionGuardConfig);
        remove_malformed!("llm_mode", LlmMode);
        remove_malformed!("approvalPolicy", ApprovalPolicyConfig);
        remove_malformed!("sandbox", SandboxConfig);
        remove_malformed!("review", ReviewConfig);
        raw
    }

    /// The raw `prompt_injection_guard` object as it appears on disk, if
    /// present. Used by [`resolve_injection_guard`] to tell a layer that
    /// *set* a field from one that merely defaulted it — so a project
    /// layer that omits `threshold` doesn't stomp the global value.
    pub(crate) fn raw_injection_guard(&self) -> Option<&Map<String, Value>> {
        self.raw
            .get("prompt_injection_guard")
            .and_then(Value::as_object)
    }

    /// The raw `preflight` object as it appears on disk, if present. Used
    /// by [`resolve_preflight`] to tell a layer that *set* a field from one
    /// that merely defaulted it.
    pub(crate) fn raw_preflight(&self) -> Option<&Map<String, Value>> {
        self.raw.get("preflight").and_then(Value::as_object)
    }

    /// Whether a top-level `key` is present in the raw config object —
    /// used by layered resolvers (e.g. [`resolve_centrality_ranking`]) to
    /// tell a layer that *set* a scalar field from one that merely
    /// defaulted it, so a layer omitting the key doesn't stomp an
    /// inherited value.
    pub(crate) fn raw_has_key(&self, key: &str) -> bool {
        self.raw.get(key).is_some()
    }

    pub fn raw_has_path(&self, path: &[&str]) -> bool {
        raw_get_path(&self.raw, path).is_some()
    }

    pub fn remove_raw_path(&mut self, path: &[&str]) -> bool {
        remove_raw_path(&mut self.raw, path)
    }

    pub fn save_raw(&self) -> Result<()> {
        let pretty = serde_json::to_string_pretty(&self.raw).context("serializing config.json")?;
        crate::config::files::ensure_parent_dir_private(&self.path)?;
        crate::config::files::write_private_file(&self.path, format!("{pretty}\n").as_bytes())
            .with_context(|| format!("writing {}", self.path.display()))?;
        Ok(())
    }

    /// Merge a typed [`ExtendedConfig`] back into the raw object and
    /// persist. Unknown keys are preserved, and absent default-valued
    /// fields stay absent so sparse project layers do not materialize
    /// inherited security policy by accident.
    pub fn write(&mut self, cfg: &ExtendedConfig) -> Result<()> {
        let obj = self
            .raw
            .as_object_mut()
            .expect("config.json root is an object");
        let serialized = serde_json::to_value(cfg).context("serializing config")?;
        let defaults = serde_json::to_value(ExtendedConfig::default())
            .context("serializing default config")?;
        if let (Value::Object(map), Value::Object(default_map)) = (&serialized, &defaults) {
            for (k, v) in map {
                if obj.contains_key(k) || default_map.get(k) != Some(v) {
                    obj.insert(k.clone(), v.clone());
                }
            }
        }
        obj.remove("trusted_only");
        obj.remove("sandboxEscalationEnabled");
        // Optional fields are skipped on serialize, so clearing them must
        // explicitly remove stale raw keys from the target layer.
        for key in [
            "utility_model",
            "translation_model",
            "cheap_code",
            "smart_code",
            "reasoning",
            "auto_title",
            "skill_injection",
            "predict_next_message_model",
            "harness_report_summarization",
            "compact_model",
            "commandResourceProfiles",
            "sandbox",
        ] {
            if serialized.get(key).is_none() {
                obj.remove(key);
            }
        }
        self.save_raw()
    }
}

fn raw_get_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut cur = value;
    for key in path {
        cur = cur.as_object()?.get(*key)?;
    }
    Some(cur)
}

fn remove_raw_path(value: &mut Value, path: &[&str]) -> bool {
    let Some((last, parents)) = path.split_last() else {
        return false;
    };
    let mut cur = value;
    for key in parents {
        let Some(next) = cur.as_object_mut().and_then(|obj| obj.get_mut(*key)) else {
            return false;
        };
        cur = next;
    }
    cur.as_object_mut()
        .and_then(|obj| obj.remove(*last))
        .is_some()
}

#[cfg(test)]
mod tests;
