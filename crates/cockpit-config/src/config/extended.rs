//! Loader for the cockpit-only config keys — the former
//! `extended-config.json` superset, now top-level keys in the single
//! per-layer `config.json` (GOALS §2a).
//!
//! Lives alongside layer-wide provider metadata in each discovered `.cockpit/`
//! directory's `config.json` (see `config::dirs`). Schema reference:
//! `the design notes` §4. All fields are optional; a missing file is fine
//! (defaults apply).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use cockpit_tokenizer::TiktokenEncoding;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub use crate::config::merge::deep_merge_value;

use crate::config::dirs::{ConfigDirKind, config_file_paths_for_load, discover_config_dirs};

mod daemon;
mod data_syntax;
mod delegation;
mod guards;
mod harness;
pub mod hooks;
mod lsp;
mod resource_scheduler;
pub mod tui;

#[allow(unused_imports)]
pub use daemon::{DaemonConfig, DaemonUploadLimitsConfig, RetentionConfig};
#[allow(unused_imports)]
pub use data_syntax::DataSyntaxConfig;
#[allow(unused_imports)]
pub use delegation::{
    DEFAULT_DELEGATION_MAX_PARALLEL, DEFAULT_RECURSIVE_SPAWN_MAX_CONCURRENCY,
    DEFAULT_RECURSIVE_SPAWN_MAX_DEPTH, DeepthinkConfig, DelegationConfig,
    DelegationRecursionPolicy, ReviewConfig, persist_review_default_participants,
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
    ArgvOverflowBehavior, DEFAULT_HARNESS_TIMEOUT_SECS, HarnessConfig, HarnessTrust,
    PromptInputMode, SystemPromptConfig, builtin_harness_presets, resolve_harnesses,
};
pub use hooks::{
    HookApplicability, HookConfigSource, HookEvent, HookEventPolicy, HookGate, HookMatcherPolicy,
    HookOrigin, HookRegistry, HookSourceKind, HookWarning, ResolvedHook, resolve_hooks_for_cwd,
    resolve_hooks_from_sources,
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
    BannerConfig, ClipboardRecovery, DiffStyle, FileIconsSetting, SleepScope, ThinkingDisplay,
    ToolCommandTemplate, TuiConfig, VimModeSetting, WebConfig, WebCustomConfig, WebProvider,
    validate_web_custom_placeholders,
};

/// A named knowledge base available to a workspace.  The source stays an
/// explicit provider-neutral reference so callers do not need to care whether
/// retrieval is local today or hosted in a future deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeBaseRegistryEntry {
    pub id: String,
    pub name: String,
    pub description: String,
    pub source: KnowledgeBaseSource,
    #[serde(rename = "embeddingOwnership")]
    pub embedding_ownership: KnowledgeBaseEmbeddingOwnership,
    #[serde(
        rename = "dreamModel",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub dream_model: Option<String>,
    #[serde(
        rename = "dreamSchedule",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub dream_schedule: Option<String>,
    /// Local-KB access policy. When enabled, only a provider/model explicitly
    /// configured as trusted may read or write this KB, including through its
    /// dream model. It does not disable content redaction. Remote KBs cannot
    /// enforce client-side model trust and are rejected when this is enabled.
    #[serde(rename = "trustRequired", default)]
    pub trust_required: bool,
    #[serde(rename = "mergePolicy")]
    pub merge_policy: KnowledgeBaseMergePolicy,

    // Workspace configuration does not get to assert a durable attachment
    // identity. For configured KBs the identity is derived from `source`, so
    // replacing a source cannot retain its predecessor's dream watermark.
    // Installed assistants are host-owned attachments whose installation ID is
    // assigned outside the workspace configuration document.
    #[serde(skip)]
    attachment_identity: Option<uuid::Uuid>,
}

impl KnowledgeBaseRegistryEntry {
    pub fn new(
        id: String,
        name: String,
        description: String,
        source: KnowledgeBaseSource,
        embedding_ownership: KnowledgeBaseEmbeddingOwnership,
        dream_model: Option<String>,
        dream_schedule: Option<String>,
        trust_required: bool,
        merge_policy: KnowledgeBaseMergePolicy,
    ) -> Self {
        Self {
            id,
            name,
            description,
            source,
            embedding_ownership,
            dream_model,
            dream_schedule,
            trust_required,
            merge_policy,
            attachment_identity: None,
        }
    }

    /// Return the identity used to scope durable dream state.
    ///
    /// A host-owned installer, or the local attachment resolver, may bind a
    /// concrete identity. Unbound workspace entries use a deterministic
    /// provisional source identity so configuration validation can identify
    /// duplicates before a local source is resolved. Durable consumers must
    /// resolve local sources before using that provisional identity.
    pub fn attachment_id(&self) -> uuid::Uuid {
        self.attachment_identity
            .unwrap_or_else(|| source_attachment_identity(&self.source))
    }

    /// Bind a concrete attachment identity assigned by its owning resolver.
    ///
    /// This is deliberately not serializable: a workspace configuration cannot
    /// retain or assert this identity.
    pub fn with_bound_attachment_identity(mut self, attachment_id: uuid::Uuid) -> Self {
        self.attachment_identity = Some(attachment_id);
        self
    }

    /// Whether an installer or source resolver has bound a concrete identity.
    pub fn has_bound_attachment_identity(&self) -> bool {
        self.attachment_identity.is_some()
    }
}

/// Validate the KB policy that does not depend on the provider catalog.
/// Remote KBs are served to arbitrary third-party agents, so a local-model
/// trust promise is unenforceable and must be rejected at config load time.
pub fn validate_knowledge_base_local_policy(entries: &[KnowledgeBaseRegistryEntry]) -> Result<()> {
    let mut ids = std::collections::BTreeSet::new();
    for entry in entries {
        if !ids.insert(&entry.id) {
            anyhow::bail!(
                "knowledge base registry contains duplicate ID `{}`",
                entry.id
            );
        }
        if matches!(&entry.source, KnowledgeBaseSource::Remote { .. }) && entry.trust_required {
            anyhow::bail!(
                "knowledge base `{}` is remote and cannot set trustRequired; trustRequired is only enforceable for local knowledge bases",
                entry.id
            );
        }
    }
    Ok(())
}

/// Validate trust-required KBs against the effective provider catalog. This is
/// intentionally a configuration boundary: a dream model that cannot access
/// its KB must never be selected or persisted and only fail later at runtime.
pub fn validate_knowledge_base_registry(
    entries: &[KnowledgeBaseRegistryEntry],
    providers: &crate::config::providers::ProvidersConfig,
) -> Result<()> {
    validate_knowledge_base_local_policy(entries)?;
    for entry in entries {
        if !entry.trust_required {
            continue;
        }
        let Some(selector) = entry
            .dream_model
            .as_deref()
            .map(str::trim)
            .filter(|selector| !selector.is_empty())
        else {
            continue;
        };
        let (provider, model) = selector
            .split_once(':')
            .or_else(|| selector.split_once('/'))
            .filter(|(provider, model)| !provider.trim().is_empty() && !model.trim().is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "knowledge base `{}` dreamModel `{selector}` must use provider:model or provider/model",
                    entry.id
                )
            })?;
        if !providers
            .resolve_trust(provider.trim(), model.trim())
            .is_trusted()
        {
            anyhow::bail!(
                "knowledge base `{}` requires a trusted dreamModel; `{selector}` is untrusted",
                entry.id
            );
        }
    }
    Ok(())
}

fn source_attachment_identity(source: &KnowledgeBaseSource) -> uuid::Uuid {
    let mut name = b"flycockpit/knowledge-attachment/v1\0".to_vec();
    match source {
        KnowledgeBaseSource::Local { path } => {
            name.extend_from_slice(b"local\0");
            name.extend_from_slice(path.to_string_lossy().as_bytes());
        }
        KnowledgeBaseSource::Remote { url } => {
            name.extend_from_slice(b"remote\0");
            name.extend_from_slice(url.as_bytes());
        }
    }
    uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, &name)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum KnowledgeBaseSource {
    Local { path: PathBuf },
    Remote { url: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum KnowledgeBaseEmbeddingOwnership {
    #[default]
    Local,
    RemoteOwned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum KnowledgeBaseMergePolicy {
    #[default]
    Auto,
    Review,
}

#[cfg(test)]
use guards::{resolve_injection_guard_from_paths, resolve_preflight_from_paths};
#[cfg(test)]
use harness::{parse_harness_config, resolve_harnesses_from_paths};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedConfig {
    /// Encoding used exclusively for locally measured response metrics.
    #[serde(default)]
    pub response_metrics_tokenizer: TiktokenEncoding,

    // NOTE: image-generation spend policy is intentionally NOT a layered
    // config field. The only authority is the immutable ledger
    // (`image_spend_policy_versions` via `activate_saved_policy`); a
    // `config.json`/remote layer must never be able to authorize paid dispatch.
    /// Image-generation endpoint/target/workflow registry.
    ///
    /// **Local-trust configuration only — never remote-supplied.** Endpoints
    /// carry origins, credential references, and request headers, so a
    /// remote/untrusted config layer must never contribute this key: it is
    /// stripped before merge (see [`strip_remote_image_generation`]), and
    /// `allow_remote_config` does not authorize remote image endpoints.
    /// Defaults to the empty registry (zero endpoints/targets/workflows,
    /// empty OpenRouter allowlist). Merged atomically as a whole-registry
    /// replace across layers (see `ATOMIC_CONFIG_VALUE_PATHS`); a
    /// present-but-invalid value fails closed to the empty registry rather
    /// than exposing a lower layer's registry.
    #[serde(default)]
    pub image_generation: crate::config::image_generation::ImageGenerationConfig,
    /// Local-trusted image-sidecar selection only.  Grant and accounting
    /// authority is deliberately daemon-owned and never lives in this layer.
    #[serde(default)]
    pub image_sidecar: crate::config::image_sidecar::SidecarSelectionConfig,
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
    /// paths for the `read`/`read` tools and re-include them in the
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

    /// User-defined bash-command templates. The webfetch/websearch tool
    /// implementations live under [`WebConfig::custom`], not this map.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub tools: HashMap<String, ToolCommandTemplate>,

    /// Provider and optional custom commands used by the built-in web tools.
    #[serde(default, skip_serializing_if = "WebConfig::is_default")]
    pub web: WebConfig,

    /// Layer-local computer-use safety policy. Catalog provider/model policy
    /// is resolved separately; explicit config layers tighten that catalog
    /// value by taking the most restrictive tier. Missing is neutral during
    /// cross-layer resolution; all-unset resolves to disabled at the final
    /// call site.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computer_use: Option<ComputerUseMode>,

    /// Display controlled by the standalone Computer primary. Real desktop is
    /// the default and remains subject to the machine-local grant; virtual is
    /// an explicit opt-in and is also suitable as a host fallback.
    #[serde(default, skip_serializing_if = "ComputerTarget::is_default")]
    pub computer_target: ComputerTarget,

    /// Layer-local opt-in for user-reviewed typed computer-use guidance
    /// proposals. Each layer (global, canonical machine-local project,
    /// provider, model) is `absent | enabled | disabled`; missing is neutral
    /// during cross-layer resolution. All-absent resolves to disabled and any
    /// explicit disable is a sticky safety veto (see
    /// `cockpit_core::computer::guidance::resolve_enablement`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_computer_guidance_proposals: Option<bool>,

    /// Opt-in to fetching remote `.well-known/cockpit` configs.
    #[serde(default)]
    pub allow_remote_config: bool,

    /// Utility model used for background work that doesn't need the
    /// primary model: session auto-titling (GOALS §17d), the
    /// prompt-injection guard when enabled, and similar small tasks.
    /// Identifier format mirrors the primary model selector
    /// (`"<provider>:<model-id>"`). Unset disables every
    /// utility-model-dependent feature. Session titling falls back to the
    /// cache-reusing active-model metadata fork when this is unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utility_model: Option<String>,

    /// Default model for knowledge-base dream orchestration. A KB-specific
    /// `dreamModel` wins; this value then falls back to `utility_model`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dream_model: Option<String>,

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

    /// Prefer the active session model for the cache-reusing, ephemeral
    /// title-and-description fork even when a title or utility model is
    /// configured. When false, a configured title/utility model is used;
    /// without one, session titling still falls back to the active model.
    #[serde(default)]
    pub auto_title_with_session_model: bool,

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

    /// Dedicated model for `/btw` side-conversation turns. Same
    /// `provider:model` shape as `compact_model`; unset/empty means inherit
    /// the parent session's current model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub btw_model: Option<String>,

    /// Dedicated embedding model selector (`provider:model` or `provider/model`).
    /// Missing means no embedding role is configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_model: Option<String>,

    /// Named knowledge bases available to this workspace. Agent definitions
    /// may narrow this registry through `allowedKnowledgeBases`.
    #[serde(default, rename = "knowledgeBases")]
    pub knowledge_bases: Vec<KnowledgeBaseRegistryEntry>,

    /// Maximum model-context budget for automatic cited knowledge injection.
    #[serde(default = "default_knowledge_inject_max_tokens")]
    pub knowledge_inject_max_tokens: usize,

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

    /// Authoritative evaluated-plan source for every media reservation.
    #[serde(rename = "mediaResources", default)]
    pub media_resources: Box<crate::config::media_budget::MediaResourcePolicy>,

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

    /// `/multireview` defaults: participants pre-selected on the next review.
    #[serde(default)]
    pub review: ReviewConfig,

    /// Goal-completion skeptic verification defaults. The driver applies this
    /// only to budgeted goals unless a later per-session override says more.
    #[serde(
        rename = "goalSupervision",
        default,
        skip_serializing_if = "GoalSupervisionConfig::is_default"
    )]
    pub goal_supervision: GoalSupervisionConfig,

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

    /// Which primary agent a new session starts on. `build` (the default)
    /// starts on the coding agent; the user may pin `plan` for plan-mode
    /// deliberation. `/settings` exposes the cycle; [`initial_active_agent`]
    /// reads this. Distinct from [`crate::agents::AgentMode`].
    ///
    /// [`initial_active_agent`]: crate::daemon::session_worker
    #[serde(rename = "defaultPrimaryAgent", default)]
    pub default_primary_agent: DefaultPrimaryAgent,

    /// Raw removed/unknown `defaultPrimaryAgent` value that degraded to
    /// [`DefaultPrimaryAgent::Build`]. This is runtime-only notice state:
    /// it is derived from config input, cloned through daemon snapshots, and
    /// intentionally omitted from serialized config/protocol output.
    #[serde(skip)]
    pub removed_default_primary_agent: Option<String>,

    /// Runtime-only tombstone recording that a loaded layer still contained
    /// the removed `llm_mode` key. It is never serialized back to config; the
    /// daemon uses it to surface the migration notice once per session.
    #[serde(skip)]
    pub removed_llm_mode: Option<String>,

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
    /// everything unprompted. `/settings` exposes
    /// the cycle; the session reads this at spawn.
    #[serde(rename = "defaultApprovalMode", default)]
    pub default_approval_mode: ApprovalMode,

    /// Consent policy for trusted-child sealed acquisition. Audit-only is the
    /// launch default; `approval` requires an owner decision before dispatch.
    #[serde(
        rename = "sealedAcquisitionConsent",
        default,
        skip_serializing_if = "SealedAcquisitionConsent::is_default"
    )]
    pub sealed_acquisition_consent: SealedAcquisitionConsent,

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

    /// Call-graph centrality ranking for `search` and `code {kind:"symbol_find"}`
    /// intel tools (GOALS §21, prompt `code-graph-centrality-and-context.md`).
    /// `true` (the default) reorders their results by how central the
    /// matched code is in the call graph — an **additive** signal that
    /// never drops or hides a result, so recall is unchanged and only the
    /// order shifts. `false` reverts both tools to their exact unranked
    /// order. Resolved by [`resolve_centrality_ranking`].
    #[serde(rename = "intelCentralityRanking", default = "default_true")]
    pub intel_centrality_ranking: bool,

    /// When true (the default), a message submitted while a run is in
    /// flight is classed `steering` and injects at the focused agent's
    /// next turn boundary. When false, it is classed `held` until the
    /// run completes; Enter on an empty composer then promotes the
    /// whole queue to steering. Per-message and box-level toggles
    /// override this default. Behavioral, not a TUI chrome setting.
    #[serde(rename = "queuedMessagesAsSteering", default = "default_true")]
    pub queued_messages_as_steering: bool,

    /// Directory names pruned from intel index walks at every depth. When
    /// unset, Cockpit uses [`DEFAULT_INTEL_EXCLUDE_DIRS`]. When set,
    /// `intel.exclude_dirs` replaces the defaults so users can extend or
    /// un-exclude names. `intel.max_cold_index_files` caps one cold freshen.
    #[serde(default, skip_serializing_if = "IntelConfig::is_default")]
    pub intel: IntelConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct IntelConfig {
    /// Directory names pruned from intel index walks at every depth. When set,
    /// this replaces the built-in default list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude_dirs: Option<Vec<String>>,

    /// Maximum number of files parsed by one cold intel freshen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cold_index_files: Option<usize>,
}

impl IntelConfig {
    fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

pub const DEFAULT_INTEL_EXCLUDE_DIRS: &[&str] = &[
    "node_modules",
    "target",
    "dist",
    "build",
    "vendor",
    "__pycache__",
    ".venv",
    "venv",
];

pub const DEFAULT_INTEL_MAX_COLD_INDEX_FILES: usize = 25_000;

/// Whether call-graph centrality ranking is enabled for `cwd` (the
/// `extended.intelCentralityRanking` config gate, default on). Resolved
/// layered — each `config.json` on the walk overlays the previous, so a
/// project layer's setting overrides a home/global one (same precedence
/// as [`resolve_preflight`]). A layer that omits the key leaves the
/// inherited value intact. When off, `search` and `code {kind:"symbol_find"}`
/// revert to today's exact ordering.
pub fn resolve_centrality_ranking(cwd: &Path) -> bool {
    let paths = config_file_paths_for_load(cwd);
    resolve_centrality_ranking_from_paths(&paths)
}

/// Resolve intel directory-name exclusions for `cwd`. A layer that sets
/// `intel.exclude_dirs` replaces the inherited list; omitted layers leave it
/// unchanged.
pub fn resolve_intel_exclude_dirs(cwd: &Path) -> Vec<String> {
    let paths = config_file_paths_for_load(cwd);
    resolve_intel_exclude_dirs_from_paths(&paths)
}

fn resolve_intel_exclude_dirs_from_paths(paths: &[PathBuf]) -> Vec<String> {
    let mut dirs = default_intel_exclude_dirs();
    for path in paths {
        if !path.exists() {
            continue;
        }
        let Ok(doc) = ExtendedConfigDoc::load(path) else {
            continue;
        };
        if let Some(intel) = doc.raw_field("intel").and_then(Value::as_object)
            && intel.contains_key("exclude_dirs")
        {
            dirs =
                normalize_intel_exclude_dirs(doc.config().intel.exclude_dirs.unwrap_or_default());
        }
    }
    dirs
}

/// Resolve the cold-index file cap for `cwd`. More-specific layers replace
/// earlier values; zero is treated as the default to avoid a footgun where
/// every cold index is immediately truncated to nothing.
pub fn resolve_intel_max_cold_index_files(cwd: &Path) -> usize {
    let paths = config_file_paths_for_load(cwd);
    resolve_intel_max_cold_index_files_from_paths(&paths)
}

fn resolve_intel_max_cold_index_files_from_paths(paths: &[PathBuf]) -> usize {
    let mut max = DEFAULT_INTEL_MAX_COLD_INDEX_FILES;
    for path in paths {
        if !path.exists() {
            continue;
        }
        let Ok(doc) = ExtendedConfigDoc::load(path) else {
            continue;
        };
        if let Some(intel) = doc.raw_field("intel").and_then(Value::as_object)
            && intel.contains_key("max_cold_index_files")
            && let Some(configured) = doc.config().intel.max_cold_index_files
        {
            max = configured.max(1);
        }
    }
    max
}

pub fn default_intel_exclude_dirs() -> Vec<String> {
    DEFAULT_INTEL_EXCLUDE_DIRS
        .iter()
        .map(|dir| (*dir).to_string())
        .collect()
}

fn normalize_intel_exclude_dirs(dirs: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for dir in dirs {
        let dir = dir.trim().trim_matches('/').to_string();
        if !dir.is_empty() && !out.contains(&dir) {
            out.push(dir);
        }
    }
    out
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
    #[serde(default, rename = "dangerousFlags")]
    pub dangerous_flags: HashMap<String, DangerousFlagRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DangerousFlagRule {
    #[serde(default)]
    pub flags: Vec<String>,
    pub tier: String,
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

/// Which primary agent a new session starts on.
/// The serde spelling is lowercase (`build`/`plan`); the resolved
/// agent name [`Self::agent_name`] keeps the in-binary casing convention
/// (capitalized primaries — `Build`/`Plan`).
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DefaultPrimaryAgent {
    /// Start directly on `Build` (make-the-change-now).
    #[default]
    Build,
    /// Start directly on `Plan` for plan-mode deliberation.
    Plan,
}

impl<'de> Deserialize<'de> for DefaultPrimaryAgent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "plan" => DefaultPrimaryAgent::Plan,
            "build" | "auto" | "swarm" => DefaultPrimaryAgent::Build,
            _ => DefaultPrimaryAgent::Build,
        })
    }
}

impl DefaultPrimaryAgent {
    /// The in-binary agent name (the capitalized primary spelling the
    /// agent factory + `swap_primary` match on).
    pub fn agent_name(self) -> &'static str {
        match self {
            DefaultPrimaryAgent::Build => "Build",
            DefaultPrimaryAgent::Plan => "Plan",
        }
    }

    /// Cycle to the next choice — the `/settings` row's toggle action.
    pub fn cycled(self) -> Self {
        match self {
            DefaultPrimaryAgent::Build => DefaultPrimaryAgent::Plan,
            DefaultPrimaryAgent::Plan => DefaultPrimaryAgent::Build,
        }
    }
}

/// Human-permission ladder for every grant-or-ask surface.
///
/// Manual asks after applicable grants are checked; Auto routes ungranted work
/// through the safety gate before asking; Yolo is unattended and opens no human
/// permission interrupt. Successful confined commands remain silent under all
/// modes — the sandbox is their gate.
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SealedAcquisitionConsent {
    #[default]
    AuditOnly,
    Approval,
}

impl SealedAcquisitionConsent {
    fn is_default(&self) -> bool {
        *self == Self::AuditOnly
    }
}

/// Computer-use reachability tier.
///
/// The declaration order is the safety order: `disabled < ask < yolo`.
/// Taking `min` over explicit layers therefore chooses the most restrictive
/// configured policy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ComputerUseMode {
    Disabled,
    Ask,
    Yolo,
}

/// Display target for the standalone Computer primary.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ComputerTarget {
    Virtual,
    #[default]
    RealDesktop,
}

impl ComputerTarget {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

impl ComputerUseMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ComputerUseMode::Disabled => "disabled",
            ComputerUseMode::Ask => "ask",
            ComputerUseMode::Yolo => "yolo",
        }
    }

    pub fn most_restrictive(values: impl IntoIterator<Item = Self>) -> Option<Self> {
        values.into_iter().min()
    }

    pub fn min_with(self, other: Self) -> Self {
        self.min(other)
    }
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

pub const SEEDED_SCAN_DIRS: [&str; 2] = ["~/.agents/skills", "./.agents/skills"];

/// Skills subsystem config (GOALS §5).
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// Additional Agent Skills-compatible roots shared with other runtimes
    /// such as Hermes. Appended after `scan_dirs`, preserving native-root
    /// precedence when package names collide.
    #[serde(default)]
    pub external_dirs: Vec<String>,

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

    /// Require a persisted user decision before foreground `skill_manage`
    /// mutations. Enabled by default: granting the tool is not consent for
    /// every durable skill-library write. Background-review writes are
    /// exempt from this config-driven gate because the review cage already
    /// enforces read-before-write and auto-denies any interrupt it raises.
    /// The ordinary parked-interrupt replay path holds the exact tool
    /// arguments until approval.
    #[serde(default = "default_true")]
    pub write_approval: bool,

    /// Allow the skill curator to lifecycle bundled or hub-installed skills.
    /// Off by default: built-in and hub material is normally treated as
    /// package-owned and skipped by deterministic pruning.
    #[serde(default)]
    pub prune_builtins: bool,

    /// Enable model-assisted skill consolidation during curator runs. The
    /// deterministic stale/archive phase remains always available; this flag
    /// only opts into the guarded LLM review phase.
    #[serde(default)]
    pub consolidate: bool,
}

impl Default for SkillsConfig {
    fn default() -> Self {
        Self {
            scan_dirs: Vec::new(),
            external_dirs: Vec::new(),
            auto_bang_commands: false,
            ancestor_walk: false,
            write_approval: default_true(),
            prune_builtins: false,
            consolidate: false,
        }
    }
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
    let docs = load_existing_docs_from_paths(paths);
    resolve_gitignore_allow_from_docs(&docs)
}

fn resolve_gitignore_allow_from_docs(docs: &[ExtendedConfigDoc]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for doc in docs {
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
#[cfg(test)]
fn resolve_redact_list_unions_from_paths(paths: &[PathBuf]) -> RedactListUnions {
    let docs = load_existing_docs_from_paths(paths);
    resolve_redact_list_unions_from_docs(&docs)
}

fn resolve_redact_list_unions_from_docs(docs: &[ExtendedConfigDoc]) -> RedactListUnions {
    let mut out = RedactListUnions::default();
    let mut denylist_seen: HashSet<String> = HashSet::new();
    let mut allowlist_seen: HashSet<String> = HashSet::new();
    let mut extra_dotenv_paths_seen: HashSet<PathBuf> = HashSet::new();

    for doc in docs {
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
    /// Extra glob patterns for secret-bearing paths. These extend, never
    /// replace, Cockpit's built-in secret-path floor.
    #[serde(default)]
    pub secret_path_patterns: Vec<String>,
    /// Minimum length for prunable candidate values. The effective floor is
    /// always at least four bytes; filesystem paths are never registered by
    /// automatic scanning regardless of this value.
    pub min_secret_length: usize,
    pub placeholder: String,
    /// User-supplied literal values redacted when they meet the table's four-byte
    /// hard minimum, even if shorter than `min_secret_length` or sourced from an
    /// allowlisted env var. Forced denylist values can intentionally match
    /// filesystem paths; automatic scanning still never registers paths.
    /// Per spec §2b merging.
    #[serde(default)]
    pub denylist: Vec<String>,
    /// User-supplied env var names to *exclude* from the redaction
    /// table on top of the built-in `ENV_ALLOWLIST` in `redact::mod`.
    /// This is name-based only; it does not allowlist arbitrary values.
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
            secret_path_patterns: vec![],
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

    /// Resolve the workspace-level half of the dream-model cascade. The
    /// per-KB override is applied by the knowledge engine.
    pub fn dream_model_ref(&self) -> Option<&str> {
        self.dream_model
            .as_deref()
            .map(str::trim)
            .filter(|model| !model.is_empty())
            .or_else(|| {
                self.utility_model
                    .as_deref()
                    .map(str::trim)
                    .filter(|model| !model.is_empty())
            })
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

    pub fn btw_model_ref(&self) -> Option<&str> {
        self.btw_model
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }

    pub fn embedding_model_ref(&self) -> Option<&str> {
        self.embedding_model
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }

    pub fn removed_default_primary_agent(&self) -> Option<&str> {
        self.removed_default_primary_agent.as_deref()
    }

    pub fn removed_llm_mode(&self) -> Option<&str> {
        self.removed_llm_mode.as_deref()
    }
}

impl Default for ExtendedConfig {
    fn default() -> Self {
        Self {
            response_metrics_tokenizer: TiktokenEncoding::default(),
            image_generation: crate::config::image_generation::ImageGenerationConfig::default(),
            image_sidecar: crate::config::image_sidecar::SidecarSelectionConfig::default(),
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
            computer_use: None,
            computer_target: ComputerTarget::default(),
            allow_computer_guidance_proposals: None,
            allow_remote_config: false,
            utility_model: None,
            dream_model: None,
            translation_model: None,
            cheap_code: None,
            smart_code: None,
            reasoning: None,
            agent_chooses_subagent_model: false,
            auto_title: None,
            auto_title_with_session_model: false,
            skill_injection: None,
            predict_next_message_model: None,
            harness_report_summarization: None,
            compact_model: None,
            btw_model: None,
            embedding_model: None,
            knowledge_bases: Vec::new(),
            knowledge_inject_max_tokens: default_knowledge_inject_max_tokens(),
            compact_prompt: None,
            prompt_injection_guard: PromptInjectionGuardConfig::default(),
            preflight: PreflightConfig::default(),
            system_prompt: SystemPromptConfig::default(),
            schedule: ScheduleConfig::default(),
            resource_scheduler: ResourceSchedulerConfig::default(),
            sandbox: SandboxConfig::default(),
            daemon: DaemonConfig::default(),
            media_resources: Box::new(crate::config::media_budget::MediaResourcePolicy::default()),
            retention: RetentionConfig::default(),
            delegation: DelegationConfig::default(),
            deepthink: DeepthinkConfig::default(),
            review: ReviewConfig::default(),
            goal_supervision: GoalSupervisionConfig::default(),
            lsp: LspConfig::default(),
            data_syntax: DataSyntaxConfig::default(),
            loop_guard: LoopGuardConfig::default(),
            max_primary_rounds: 0,
            dialog: DialogConfig::default(),
            skills: SkillsConfig::default(),
            default_primary_agent: DefaultPrimaryAgent::default(),
            removed_default_primary_agent: None,
            removed_llm_mode: None,
            translation: TranslationConfig::default(),
            sandbox_escalation_enabled: true,
            default_approval_mode: ApprovalMode::default(),
            sealed_acquisition_consent: SealedAcquisitionConsent::default(),
            approval_policy: ApprovalPolicyConfig::default(),
            predict_next_message: PredictNextMessage::default(),
            shell_compression: ShellCompression::default(),
            command_resource_profiles: CommandResourceProfilesConfig::default(),
            inline_think: default_true(),
            hint_tool_call_corrections: false,
            text_embedded_recovery: TextEmbeddedRecovery::default(),
            intel_centrality_ranking: default_true(),
            queued_messages_as_steering: default_true(),
            intel: IntelConfig::default(),
        }
    }
}

pub const DEFAULT_GOAL_SUPERVISION_TOKEN_BUDGET: i64 = 200_000;
pub const DEFAULT_GOAL_SUPERVISION_COLD_SKEPTIC_COUNT: usize = 3;
pub const DEFAULT_GOAL_SUPERVISION_MAX_VERIFICATION_ATTEMPTS: u32 = 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoalSupervisionConfig {
    /// Global operator kill switch. This field is not overridable by an agent
    /// or session policy.
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(
        rename = "defaultTokenBudget",
        default = "default_goal_supervision_token_budget"
    )]
    pub default_token_budget: i64,
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
    /// Number of parallel refute-framed skeptics per verification round.
    #[serde(
        rename = "coldSkepticCount",
        default = "default_goal_supervision_cold_skeptic_count"
    )]
    pub cold_skeptic_count: usize,
    /// Optional model selector (`provider:model-id`) for skeptic agents.
    /// Unset falls back to the session model.
    #[serde(
        rename = "coldSkepticModel",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cold_skeptic_model: Option<String>,
    /// Failed/inconclusive rounds before the driver stops and surfaces
    /// `verification_failed`.
    #[serde(
        rename = "maxVerificationAttempts",
        default = "default_goal_supervision_max_verification_attempts"
    )]
    pub max_verification_attempts: u32,
}

impl GoalSupervisionConfig {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    pub fn effective_cold_skeptic_count(&self) -> usize {
        self.cold_skeptic_count.max(1)
    }

    pub fn effective_max_verification_attempts(&self) -> u32 {
        self.max_verification_attempts.max(1)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.default_token_budget <= 0 {
            anyhow::bail!("goalSupervision.defaultTokenBudget must be positive");
        }
        if !(1..=5).contains(&self.cold_skeptic_count) {
            anyhow::bail!("goalSupervision.coldSkepticCount must be between 1 and 5");
        }
        if self.max_verification_attempts == 0 {
            anyhow::bail!("goalSupervision.maxVerificationAttempts must be positive");
        }
        for selector in [
            self.planner_model.as_deref(),
            self.evaluator_model.as_deref(),
            self.gatekeeper_model.as_deref(),
            self.cold_skeptic_model.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            let Some((provider, model)) = crate::config::provider::split_provider_model(selector)
            else {
                anyhow::bail!("goalSupervision model selectors must use provider/model form");
            };
            if provider.trim().is_empty() || model.trim().is_empty() {
                anyhow::bail!("goalSupervision model selectors must use provider/model form");
            }
        }
        Ok(())
    }
}

impl Default for GoalSupervisionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_token_budget: DEFAULT_GOAL_SUPERVISION_TOKEN_BUDGET,
            planner_model: None,
            evaluator_model: None,
            gatekeeper_model: None,
            cold_skeptic_count: DEFAULT_GOAL_SUPERVISION_COLD_SKEPTIC_COUNT,
            cold_skeptic_model: None,
            max_verification_attempts: DEFAULT_GOAL_SUPERVISION_MAX_VERIFICATION_ATTEMPTS,
        }
    }
}

fn default_goal_supervision_cold_skeptic_count() -> usize {
    DEFAULT_GOAL_SUPERVISION_COLD_SKEPTIC_COUNT
}

fn default_goal_supervision_max_verification_attempts() -> u32 {
    DEFAULT_GOAL_SUPERVISION_MAX_VERIFICATION_ATTEMPTS
}

fn default_goal_supervision_token_budget() -> i64 {
    DEFAULT_GOAL_SUPERVISION_TOKEN_BUDGET
}

fn default_agent_guidance_files() -> Vec<String> {
    vec!["AGENTS.md".into()]
}

fn default_knowledge_inject_max_tokens() -> usize {
    2048
}

thread_local! {
    static LOAD_FOR_CWD_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static CONFIG_LAYER_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub fn reset_load_for_cwd_call_count() {
    LOAD_FOR_CWD_CALLS.with(|calls| calls.set(0));
}

pub fn load_for_cwd_call_count() -> usize {
    LOAD_FOR_CWD_CALLS.with(std::cell::Cell::get)
}

pub fn reset_config_layer_read_count() {
    CONFIG_LAYER_READS.with(|calls| calls.set(0));
}

pub fn config_layer_read_count() -> usize {
    CONFIG_LAYER_READS.with(std::cell::Cell::get)
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
    load_for_cwd_with_computer_use_policy(cwd).0
}

/// Effective config plus the non-secret warnings raised while merging the
/// layered documents. This is the real layered load path's warning channel:
/// it surfaces fail-closed events that happen during layer merge (e.g. a
/// present-but-invalid `image_generation` registry replaced with the empty
/// registry) which the plain [`load_for_cwd`] discards. Warnings are
/// field/path-only and never include deserialization error strings.
pub fn load_for_cwd_with_warnings(cwd: &Path) -> (ExtendedConfig, Vec<String>) {
    LOAD_FOR_CWD_CALLS.with(|calls| calls.set(calls.get() + 1));
    let paths = config_file_paths_for_load(cwd);
    let docs = load_existing_docs_from_paths(&paths);
    resolve_loaded_docs_with_warnings(&docs)
}

/// Load the effective config and the most-restrictive computer-use policy
/// from one captured set of layered documents.
pub fn load_for_cwd_with_computer_use_policy(
    cwd: &Path,
) -> (ExtendedConfig, Option<ComputerUseMode>) {
    LOAD_FOR_CWD_CALLS.with(|calls| calls.set(calls.get() + 1));
    let paths = config_file_paths_for_load(cwd);
    let docs = load_existing_docs_from_paths(&paths);
    let computer_use = resolve_computer_use_policy_from_docs(&docs);
    (resolve_loaded_docs(&docs), computer_use)
}

fn resolve_loaded_docs(docs: &[ExtendedConfigDoc]) -> ExtendedConfig {
    resolve_loaded_docs_with_warnings(docs).0
}

fn resolve_loaded_docs_with_warnings(docs: &[ExtendedConfigDoc]) -> (ExtendedConfig, Vec<String>) {
    if !docs.is_empty() {
        let (mut cfg, warnings) = load_merged_from_docs_with_warnings(docs);
        cfg.gitignore_allow = resolve_gitignore_allow_from_docs(docs);
        let redact_unions = resolve_redact_list_unions_from_docs(docs);
        cfg.redact.denylist = redact_unions.denylist;
        cfg.redact.allowlist = redact_unions.allowlist;
        cfg.redact.extra_dotenv_paths = redact_unions.extra_dotenv_paths;
        return (cfg, warnings);
    }
    // Fresh install: no config on disk. Materialize the seeded
    // skills scan-dirs so new users discover (and see in `/settings`) the
    // default skill directories.
    (
        ExtendedConfig {
            skills: SkillsConfig::seeded_default(),
            ..Default::default()
        },
        Vec::new(),
    )
}

/// Daemon-only effective loader. Existing settings/bootstrap callers remain
/// advisory, while an explicitly present malformed response tokenizer in any
/// participating (trust-filtered) readable layer rejects daemon adoption.
#[derive(Debug)]
pub struct DaemonExtendedConfigLoad {
    pub providers: crate::config::providers::ProvidersConfig,
    /// Stable, secret-free warnings from provider-layer enforcement.
    pub provider_warnings: Vec<String>,
    pub config: ExtendedConfig,
    pub response_metrics_tokenizer_validation:
        std::result::Result<(), InvalidResponseMetricsTokenizer>,
    pub participating_layers: Vec<PathBuf>,
}

/// Resolve trusted ambient layers plus an already-captured workspace layer.
/// The caller must run this under an `IgnoreConfig` workspace trust policy so
/// `cwd` discovery contributes only ambient/home/machine layers; the supplied
/// snapshot is then the sole project-layer input.  This separation prevents a
/// parser from reopening the mutable workspace pathname after attachment.
pub fn load_for_cwd_for_daemon_contract_with_workspace_layer(
    cwd: &Path,
    workspace: &crate::config::WorkspaceConfigLayerSnapshotChain,
) -> Result<DaemonExtendedConfigLoad> {
    LOAD_FOR_CWD_CALLS.with(|calls| calls.set(calls.get() + 1));
    // A complete retained chain (the explicit override is the one-layer
    // case) is already the entire effective config. Its acquisition is
    // capability-bound in the daemon, so ambient path discovery must not add
    // home/machine layers beside it. An empty (ignore-config) chain keeps the
    // historical ambient explicit behavior.
    let paths = if workspace.exclusive {
        Vec::new()
    } else {
        config_file_paths_for_load(cwd)
    };
    let (ambient_providers, captured, mut provider_warnings) =
        crate::config::providers::ConfigDoc::try_load_effective_with_layer_snapshot(&paths)?;
    let mut merged_providers = serde_json::to_value(ambient_providers)
        .context("serializing ambient provider configuration")?;
    for layer in &workspace.layers {
        let (workspace_providers, warnings) =
            crate::config::providers::ConfigDoc::providers_from_workspace_layer_snapshot_with_warnings(layer)?;
        provider_warnings.extend(warnings);
        let workspace_provider_value = serde_json::to_value(workspace_providers)
            .context("serializing retained workspace provider configuration")?;
        deep_merge_value(&mut merged_providers, &workspace_provider_value);
    }
    let providers = serde_json::from_value(merged_providers)
        .context("projecting retained workspace provider configuration")?;

    let mut docs: Vec<_> = captured
        .into_iter()
        .map(|(path, raw)| ExtendedConfigDoc {
            path,
            raw,
            origin: ConfigLayerOrigin::LocalTrusted,
        })
        .collect();
    for layer in &workspace.layers {
        docs.push(extended_doc_from_workspace_snapshot(layer)?);
    }
    let mut validation = Ok(());
    for doc in &docs {
        if let Some(value) = doc.raw_field("response_metrics_tokenizer")
            && let Err(source) = serde_json::from_value::<TiktokenEncoding>(value.clone())
            && validation.is_ok()
        {
            validation = Err(InvalidResponseMetricsTokenizer {
                path: doc.path.clone(),
                source,
            });
        }
    }
    let participating_layers = docs.iter().map(|doc| doc.path.clone()).collect();
    let config = resolve_loaded_docs(&docs);
    validate_knowledge_base_registry(&config.knowledge_bases, &providers)
        .context("invalid knowledge-base trust configuration")?;
    validate_local_knowledge_root_overlaps(cwd, &config.knowledge_bases)
        .context("invalid knowledge-base trust configuration")?;
    Ok(DaemonExtendedConfigLoad {
        providers,
        provider_warnings,
        config,
        response_metrics_tokenizer_validation: validation,
        participating_layers,
    })
}

fn extended_doc_from_workspace_snapshot(
    workspace: &crate::config::WorkspaceConfigLayerSnapshot,
) -> Result<ExtendedConfigDoc> {
    let raw = parse_config_root_object(workspace.config_json.as_deref().unwrap_or(b"{}"))?;
    Ok(ExtendedConfigDoc {
        // Never expose the attachment path in diagnostics or wire data. The
        // source label identifies provenance without becoming filesystem data.
        path: PathBuf::from("<attached workspace config>"),
        raw,
        origin: ConfigLayerOrigin::LocalTrusted,
    })
}

pub fn load_for_cwd_for_daemon_contract(cwd: &Path) -> Result<DaemonExtendedConfigLoad> {
    LOAD_FOR_CWD_CALLS.with(|calls| calls.set(calls.get() + 1));
    let paths = config_file_paths_for_load(cwd);
    // Provider recovery/migration is a barrier. Only after it completes do we
    // capture every readable participating config layer once; providers,
    // extended settings, strict validation, and provenance are all projected
    // from that one trust-filtered snapshot.
    let (providers, captured, provider_warnings) =
        crate::config::providers::ConfigDoc::try_load_effective_with_layer_snapshot(&paths)?;
    let docs: Vec<_> = captured
        .into_iter()
        .map(|(path, raw)| ExtendedConfigDoc {
            path,
            raw,
            origin: ConfigLayerOrigin::LocalTrusted,
        })
        .collect();
    let mut validation = Ok(());
    for doc in &docs {
        if let Some(value) = doc.raw_field("response_metrics_tokenizer")
            && let Err(source) = serde_json::from_value::<TiktokenEncoding>(value.clone())
            && validation.is_ok()
        {
            validation = Err(InvalidResponseMetricsTokenizer {
                path: doc.path.clone(),
                source,
            });
        }
    }
    let participating_layers = docs.iter().map(|doc| doc.path.clone()).collect();
    let config = resolve_loaded_docs(&docs);
    validate_knowledge_base_registry(&config.knowledge_bases, &providers)
        .context("invalid knowledge-base trust configuration")?;
    validate_local_knowledge_root_overlaps(cwd, &config.knowledge_bases)
        .context("invalid knowledge-base trust configuration")?;
    Ok(DaemonExtendedConfigLoad {
        providers,
        provider_warnings,
        config,
        response_metrics_tokenizer_validation: validation,
        participating_layers,
    })
}

fn validate_local_knowledge_root_overlaps(
    cwd: &Path,
    entries: &[KnowledgeBaseRegistryEntry],
) -> Result<()> {
    let mut roots: Vec<(&str, PathBuf)> = Vec::new();
    for entry in entries {
        let KnowledgeBaseSource::Local { path } = &entry.source else {
            continue;
        };
        let root = if path.is_absolute() {
            path.clone()
        } else {
            cwd.join(path)
        };
        let root = resolve_effective_local_knowledge_root(&root).with_context(|| {
            format!(
                "resolving configured local knowledge base `{}` root `{}` for overlap validation",
                entry.id,
                root.display()
            )
        })?;
        for (existing_id, existing_root) in &roots {
            // Both roots have already passed `resolve_effective_local_knowledge_root`,
            // which resolves symlinks through their nearest existing ancestors and
            // preserves only a normalized unresolved tail. Component-wise prefix
            // matching therefore detects equality and nesting without making the
            // config leaf depend upward on `cockpit-host`.
            if existing_root.starts_with(&root) || root.starts_with(existing_root) {
                anyhow::bail!(
                    "local knowledge bases `{}` and `{}` resolve to overlapping roots (`{}` and `{}`)",
                    existing_id,
                    entry.id,
                    existing_root.display(),
                    root.display()
                );
            }
        }
        roots.push((entry.id.as_str(), root));
    }
    Ok(())
}

fn resolve_effective_local_knowledge_root(path: &Path) -> Result<PathBuf> {
    let mut current = path;
    loop {
        match std::fs::canonicalize(current) {
            Ok(base) => return append_unresolved_tail(base, path, current),
            Err(err) => {
                if std::fs::symlink_metadata(current)
                    .map(|meta| meta.file_type().is_symlink())
                    .unwrap_or(false)
                {
                    anyhow::bail!("symlink `{}` cannot be resolved: {err}", current.display());
                }
                let Some(parent) = current.parent() else {
                    anyhow::bail!("no existing parent for `{}`", path.display());
                };
                if parent == current {
                    anyhow::bail!("no existing parent for `{}`", path.display());
                }
                current = parent;
            }
        }
    }
}

fn append_unresolved_tail(
    mut base: PathBuf,
    original: &Path,
    existing_prefix: &Path,
) -> Result<PathBuf> {
    let tail = original
        .strip_prefix(existing_prefix)
        .unwrap_or_else(|_| Path::new(""));
    for component in tail.components() {
        match component {
            std::path::Component::Normal(part) => base.push(part),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                anyhow::bail!("unresolved parent traversal in `{}`", original.display());
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {}
        }
    }
    if base.file_name() == Some(OsStr::new("..")) {
        anyhow::bail!("unresolved parent traversal in `{}`", original.display());
    }
    Ok(base)
}

#[derive(Debug)]
pub struct InvalidResponseMetricsTokenizer {
    path: PathBuf,
    source: serde_json::Error,
}

impl InvalidResponseMetricsTokenizer {
    pub fn diagnostic(&self) -> String {
        format!("{}: {}", self.path.display(), self.source)
    }
}

impl std::fmt::Display for InvalidResponseMetricsTokenizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("configuration value is invalid")
    }
}

impl std::error::Error for InvalidResponseMetricsTokenizer {}

fn read_extended_config_doc(path: &Path) -> Result<ExtendedConfigDoc> {
    CONFIG_LAYER_READS.with(|calls| calls.set(calls.get() + 1));
    ExtendedConfigDoc::load(path)
}

fn load_existing_docs_from_paths(paths: &[PathBuf]) -> Vec<ExtendedConfigDoc> {
    let mut docs = Vec::new();
    for path in paths {
        if !path.exists() {
            continue;
        }
        match read_extended_config_doc(path) {
            Ok(doc) => docs.push(doc),
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "skipping malformed config layer");
            }
        }
    }
    docs
}

fn load_merged_from_docs_with_warnings(
    docs: &[ExtendedConfigDoc],
) -> (ExtendedConfig, Vec<String>) {
    let mut merged =
        serde_json::to_value(ExtendedConfig::default()).unwrap_or(Value::Object(Map::new()));
    let mut warnings = Vec::new();
    for doc in docs {
        let layer = doc.raw_for_layer_merge(&mut warnings);
        deep_merge_value(&mut merged, &layer);
    }
    let cfg = ExtendedConfigDoc {
        path: PathBuf::from("<merged effective config>"),
        raw: merged,
        origin: ConfigLayerOrigin::LocalTrusted,
    }
    .config();
    (cfg, warnings)
}

/// Resolve the explicitly configured computer-use policy across all config
/// layers for `cwd`. Missing layers and layers without `computer_use` are
/// neutral; malformed values are ignored with the same warning posture as the
/// normal extended-config loader. The caller combines this with catalog
/// provider/model policy and applies the final all-unset disabled default.
pub fn resolve_computer_use_policy_for_cwd(cwd: &Path) -> Option<ComputerUseMode> {
    let paths = config_file_paths_for_load(cwd);
    resolve_computer_use_policy_from_paths(&paths)
}

pub fn resolve_computer_use_policy_from_paths(paths: &[PathBuf]) -> Option<ComputerUseMode> {
    let mut tiers = Vec::new();
    for path in paths {
        if !path.exists() {
            continue;
        }
        match ExtendedConfigDoc::load(path) {
            Ok(doc) => {
                let Some(value) = doc.raw_field("computer_use") else {
                    continue;
                };
                match serde_json::from_value::<ComputerUseMode>(value.clone()) {
                    Ok(tier) => tiers.push(tier),
                    Err(error) => {
                        tracing::warn!(
                            path = %path.display(),
                            key = "computer_use",
                            %error,
                            "skipping malformed computer_use policy"
                        );
                    }
                }
            }
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "skipping malformed config layer");
            }
        }
    }
    ComputerUseMode::most_restrictive(tiers)
}

fn resolve_computer_use_policy_from_docs(docs: &[ExtendedConfigDoc]) -> Option<ComputerUseMode> {
    ComputerUseMode::most_restrictive(docs.iter().filter_map(|doc| {
        let value = doc.raw_field("computer_use")?;
        match serde_json::from_value::<ComputerUseMode>(value.clone()) {
            Ok(tier) => Some(tier),
            Err(error) => {
                tracing::warn!(
                    path = %doc.path.display(),
                    key = "computer_use",
                    %error,
                    "skipping malformed computer_use policy"
                );
                None
            }
        }
    }))
}

/// The two document-scoped layers of `allow_computer_guidance_proposals`,
/// read separately (NOT combined most-restrictively like `computer_use`).
///
/// Each slot is `absent | enabled | disabled` encoded as `Option<bool>`
/// (`None | Some(true) | Some(false)`). The provider and model layers are
/// read separately by the caller from the provider catalog; these two doc
/// layers are the global (home-scoped) and canonical machine-local project
/// layers. cockpit-config cannot depend on cockpit-core, so this returns raw
/// `Option<bool>` values for cockpit-core to map into `EnablementLayers` and
/// feed to `resolve_enablement`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GuidanceProposalDocLayers {
    /// Global (home-scoped) layer value.
    pub global: Option<bool>,
    /// Canonical machine-local project layer value.
    pub project: Option<bool>,
}

/// Project the guidance layer values from the exact retained daemon snapshot
/// without reopening any path. Each retained layer carries its exact
/// attach-time discovery origin, so home layers fold into the global slot and
/// machine-local and every project layer fold into the project slot regardless
/// of precedence position. An explicit one-file override is project scoped.
pub fn guidance_proposal_doc_layers_from_snapshot_chain(
    chain: &crate::config::WorkspaceConfigLayerSnapshotChain,
) -> Result<GuidanceProposalDocLayers> {
    let mut out = GuidanceProposalDocLayers::default();
    for layer in &chain.layers {
        let doc = extended_doc_from_workspace_snapshot(layer)?;
        let value = guidance_proposal_field_from_doc(&doc);
        match layer.origin.as_ref() {
            Some(ConfigDirKind::HomeXdg) => {
                out.global = fold_enablement_value(out.global, value);
            }
            Some(ConfigDirKind::MachineLocal | ConfigDirKind::Project) | None => {
                out.project = fold_enablement_value(out.project, value);
            }
        }
    }
    Ok(out)
}

/// Fold a newly seen layer value into an accumulated slot, preserving the
/// sticky-disable-wins / else-enable / else-absent algebra that
/// `resolve_enablement` applies across layers. Multiple discovered
/// directories can map to the same doc slot (e.g. both home-scoped
/// directories are "global"); a disable in any of them stays a veto.
fn fold_enablement_value(acc: Option<bool>, next: Option<bool>) -> Option<bool> {
    match (acc, next) {
        (Some(false), _) | (_, Some(false)) => Some(false),
        (Some(true), _) | (_, Some(true)) => Some(true),
        (None, None) => None,
    }
}

/// Read the `allow_computer_guidance_proposals` field from a single config
/// document, applying the same malformed-value posture as the computer_use
/// resolver: a present-but-malformed value is skipped (treated as absent)
/// with a field-only warning.
fn guidance_proposal_field_from_doc(doc: &ExtendedConfigDoc) -> Option<bool> {
    let value = doc.raw_field("allow_computer_guidance_proposals")?;
    match serde_json::from_value::<Option<bool>>(value.clone()) {
        Ok(parsed) => parsed,
        Err(error) => {
            tracing::warn!(
                path = %doc.path.display(),
                key = "allow_computer_guidance_proposals",
                %error,
                "skipping malformed allow_computer_guidance_proposals value"
            );
            None
        }
    }
}

/// Resolve the global and canonical machine-local project doc layers of
/// `allow_computer_guidance_proposals` for `cwd`.
///
/// The platform global config directory folds into the global slot; the
/// machine-local per-cwd directory and any project
/// `.cockpit` directories fold into the project slot. When `COCKPIT_CONFIG`
/// selects a single file, that file is the effective (most-specific) layer and
/// its value is treated as the project slot.
pub fn resolve_guidance_proposal_doc_layers_for_cwd(cwd: &Path) -> GuidanceProposalDocLayers {
    // Honor the single-file override exactly as config_file_paths_for_load
    // does: it collapses discovery to one concrete file.
    if let Some(path) = std::env::var_os(crate::config::dirs::COCKPIT_CONFIG_ENV)
        && !path.is_empty()
    {
        let mut layers = GuidanceProposalDocLayers::default();
        for path in config_file_paths_for_load(cwd) {
            if !path.exists() {
                continue;
            }
            match ExtendedConfigDoc::load(&path) {
                Ok(doc) => {
                    layers.project = fold_enablement_value(
                        layers.project,
                        guidance_proposal_field_from_doc(&doc),
                    );
                }
                Err(error) => {
                    tracing::warn!(path = %path.display(), %error, "skipping malformed config layer");
                }
            }
        }
        return layers;
    }

    let mut layers = GuidanceProposalDocLayers::default();
    for dir in discover_config_dirs(cwd) {
        let path = dir.path.join(crate::config::dirs::CONFIG_FILE);
        if !path.exists() {
            continue;
        }
        let doc = match ExtendedConfigDoc::load(&path) {
            Ok(doc) => doc,
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "skipping malformed config layer");
                continue;
            }
        };
        let value = guidance_proposal_field_from_doc(&doc);
        match dir.kind {
            ConfigDirKind::HomeXdg => {
                layers.global = fold_enablement_value(layers.global, value);
            }
            ConfigDirKind::MachineLocal | ConfigDirKind::Project => {
                layers.project = fold_enablement_value(layers.project, value);
            }
        }
    }
    layers
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
    origin: ConfigLayerOrigin,
}

/// Trust origin of a captured config layer.
///
/// Today the layered loader only walks local, trust-filtered paths
/// ([`config_file_paths_for_load`] / [`discover_config_dirs`]), so every
/// captured layer is [`ConfigLayerOrigin::LocalTrusted`]. [`ConfigLayerOrigin::Remote`]
/// is the reserved extension point for a future `.well-known/cockpit` fetch:
/// remote layers are stripped of `image_generation` before merge by
/// [`ExtendedConfigDoc::raw_for_layer_merge`] via [`strip_remote_image_generation`],
/// so a remote origin can never inject endpoints, credential refs, or
/// workflows even when `allow_remote_config` is enabled.
///
/// SECURITY: this enum deliberately has **no** `Default`. Origin must be stated
/// explicitly at every [`ExtendedConfigDoc`] construction so a
/// remote/untrusted source can never be treated as trusted by omission. The
/// only supported way to introduce a non-local-trusted layer is
/// [`ExtendedConfigDoc::from_remote_layer`], which stamps `Remote`; `load`
/// stamps `LocalTrusted` precisely because it only reads local trust-filtered
/// paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigLayerOrigin {
    LocalTrusted,
    Remote,
}

/// Neutralize a remote/untrusted config layer's `image_generation`
/// contribution, regardless of raw shape.
///
/// Remote / untrusted layers must never contribute an image-generation
/// registry: endpoints carry origins, credential references, and request
/// headers, and `allow_remote_config` opts in only to remote *scalar*
/// settings, never to image-generation endpoints. For an object layer we
/// *remove* the `image_generation` key (rather than replacing it with `{}`),
/// so the layer behaves exactly as if it never set the field and a lower
/// **local** layer's registry is inherited unchanged — the opposite of the
/// malformed-**local** fail-closed path in
/// [`ExtendedConfigDoc::raw_for_layer_merge`], which replaces the value with
/// `{}` to wipe (never inherit) a broken local layer. A **non-object** remote
/// raw (`null` / string / array) carries no usable config and, left as-is,
/// would clobber the entire accumulated local config via `deep_merge_value`
/// (which replaces a base wholesale for a non-object overlay); neutralize it
/// to an empty object so it can neither supply nor wipe the registry.
///
/// Applied at the single construction funnel [`ExtendedConfigDoc::from_remote_layer`]
/// (so a remote doc's stored `raw` never carries `image_generation`, and every
/// typed-parse and merge path is safe with no per-path guard), and again in
/// [`ExtendedConfigDoc::raw_for_layer_merge`] as defense-in-depth.
pub(crate) fn strip_remote_image_generation(raw: &mut Value) {
    match raw.as_object_mut() {
        Some(obj) => {
            obj.remove("image_generation");
        }
        None => *raw = Value::Object(Map::new()),
    }
}

/// Remote configuration cannot select an image-sidecar destination.  Even a
/// model identifier is egress-relevant input, and a remote layer must not
/// influence a local owner's sidecar routing policy.
pub(crate) fn strip_remote_image_sidecar(raw: &mut Value) {
    if let Some(obj) = raw.as_object_mut() {
        obj.remove("image_sidecar");
    }
}

/// Parse config.json bytes into an object root, mirroring
/// [`ExtendedConfigDoc::load`]: empty/whitespace bytes are an empty object, and
/// a non-object root is rejected (fail closed). Shared by the layered loader's
/// posture and the `SaveExtendedConfig` merge below.
fn parse_config_root_object(bytes: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(bytes).context("config.json is not valid UTF-8")?;
    if text.trim().is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    let value: Value = serde_json::from_str(text).context("config.json is not valid JSON")?;
    match value {
        Value::Object(_) => Ok(value),
        other => anyhow::bail!("expected config.json root to be an object, found {other:?}"),
    }
}

/// Render the config.json bytes to persist for a daemon `SaveExtendedConfig`
/// write, preserving the on-disk `image_generation` registry.
///
/// DATA-LOSS / SECURITY: `SaveExtendedConfig` is NEVER the authoritative writer
/// of `image_generation`. The daemon redacts the registry to the empty default
/// (`ImageGenerationConfig::default`, via `redacted_for_snapshot`) before it
/// sends a config snapshot to any client, so a client that round-trips that
/// snapshot back through `SaveExtendedConfig` always carries an EMPTY
/// `image_generation`. A verbatim write would therefore WIPE the on-disk
/// endpoints/targets/workflows/allowlist on any generic settings save.
/// `image_generation` is mutated ONLY through the dedicated `image_endpoint_*` /
/// `image_target_*` RPCs, so this UNCONDITIONALLY strips whatever the incoming
/// doc claims for `image_generation` (reusing [`strip_remote_image_generation`],
/// the same field-owned-by-the-local-layer machinery that keeps a remote layer
/// from authoring or wiping the registry) and re-applies the current on-disk
/// value — taking every OTHER config section verbatim from the incoming doc. A
/// legitimate "clear all image config" goes through the dedicated delete RPCs,
/// never here.
///
/// Fails closed if either document is not a JSON object root (mirrors
/// [`ExtendedConfigDoc::load`]), so a malformed on-disk config cannot silently
/// drop a present-but-unreadable registry, and a malformed incoming payload is
/// rejected rather than written.
pub fn render_saved_extended_config_preserving_image_generation(
    incoming_bytes: &[u8],
    on_disk_bytes: &[u8],
) -> Result<Vec<u8>> {
    let mut incoming = parse_config_root_object(incoming_bytes)
        .context("parsing incoming SaveExtendedConfig config.json")?;
    // The client can never author `image_generation`; drop whatever it sent
    // (the redacted round-trip always sends the empty registry).
    strip_remote_image_generation(&mut incoming);
    // Re-apply the on-disk registry so a generic settings save preserves it.
    let on_disk = parse_config_root_object(on_disk_bytes).context("parsing on-disk config.json")?;
    if let (Some(incoming_obj), Some(on_disk_registry)) =
        (incoming.as_object_mut(), on_disk.get("image_generation"))
    {
        incoming_obj.insert("image_generation".into(), on_disk_registry.clone());
    }
    let pretty =
        serde_json::to_string_pretty(&incoming).context("serializing merged config.json")?;
    Ok(format!("{pretty}\n").into_bytes())
}

/// Installation-scoped KEK placement is never a layered config key. Strip
/// `secretStore` / `secret_store` from every layer so project and remote
/// documents cannot select, promote, or persist it.
pub(crate) fn strip_secret_store_key(raw: &mut Value) {
    if let Some(obj) = raw.as_object_mut() {
        obj.remove("secretStore");
        obj.remove("secret_store");
    }
}

/// Stable, secret-free warning for a malformed `image_generation` value.
/// Deliberately omits BOTH the deserialization/validation error (whose `{:?}`
/// rendering can embed attacker-supplied credential-like strings) AND the
/// config file path (which can itself carry a secret, e.g. a token-named
/// directory or `COCKPIT_CONFIG=/secrets/<token>/config.json`). Names only the
/// field so nothing secret can ride along.
fn image_generation_malformed_warning() -> String {
    "ignored malformed `image_generation` configuration".to_string()
}

impl ExtendedConfigDoc {
    /// Load a config layer from a LOCAL path and stamp it
    /// [`ConfigLayerOrigin::LocalTrusted`].
    ///
    /// SECURITY: this is the local-trusted loader. It is only ever handed
    /// config paths that have already passed the `dirs.rs` workspace-trust
    /// filter (`config_file_paths_for_load` / `discover_config_dirs`), so the
    /// content it reads is by definition local-trusted — a file on such a path
    /// is equivalent to the user having placed it there, and a file carries no
    /// origin metadata for `load` to infer otherwise. Consequently `load`
    /// does NOT strip `image_generation`.
    ///
    /// Any REMOTE / untrusted config source (e.g. a future `.well-known/cockpit`
    /// fetch) MUST be constructed via [`Self::from_remote_layer`] — never
    /// cached to a file and read back through `load` — so its origin is stamped
    /// [`ConfigLayerOrigin::Remote`] and `image_generation` is stripped at
    /// construction. See the [`ConfigLayerOrigin`] invariant.
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
        let mut raw = match raw {
            Value::Object(_) => raw,
            other => {
                anyhow::bail!("expected config.json root to be an object, found {other:?}")
            }
        };
        strip_secret_store_key(&mut raw);
        Ok(Self {
            path: path.to_path_buf(),
            raw,
            // Only local, trust-filtered paths reach this loader today.
            origin: ConfigLayerOrigin::LocalTrusted,
        })
    }

    /// SECURITY: the ONLY supported way to introduce a config layer sourced
    /// from a REMOTE / untrusted origin (e.g. a future `.well-known/cockpit`
    /// fetch). It stamps [`ConfigLayerOrigin::Remote`], so
    /// [`Self::raw_for_layer_merge`] strips `image_generation` before merge and
    /// a remote origin can never inject endpoints, credential refs, or
    /// workflows (nor wipe a lower local registry). [`Self::load`] stamps
    /// `LocalTrusted` precisely because it only reads local trust-filtered
    /// paths; any new remote source MUST route through this constructor rather
    /// than reusing `load`, so the strip cannot be forgotten. `raw` is accepted
    /// as-is (any JSON shape) — a non-object remote layer is neutralized here —
    /// because remote responses are not pre-validated to be objects.
    ///
    /// SECURITY: `image_generation` is stripped from `raw` IMMEDIATELY, at this
    /// single construction funnel, so the stored `raw` never carries it. Every
    /// downstream path — [`Self::config`], [`Self::config_with_warnings`], and
    /// [`Self::raw_for_layer_merge`] — then yields the empty registry for a
    /// remote source with no per-parse-path guard to forget.
    pub fn from_remote_layer(mut raw: Value) -> Self {
        strip_remote_image_generation(&mut raw);
        strip_remote_image_sidecar(&mut raw);
        strip_secret_store_key(&mut raw);
        Self {
            path: PathBuf::from("<remote .well-known/cockpit>"),
            raw,
            origin: ConfigLayerOrigin::Remote,
        }
    }

    /// Whether this layer originated from a remote/untrusted source (see
    /// [`Self::from_remote_layer`]). The gate for [`strip_remote_image_generation`]
    /// in [`Self::raw_for_layer_merge`]. `false` for every layer produced by
    /// [`Self::load`], which only walks local trust-filtered paths.
    fn layer_is_remote(&self) -> bool {
        matches!(self.origin, ConfigLayerOrigin::Remote)
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
        parse_field!("response_metrics_tokenizer", response_metrics_tokenizer);
        // `image_spend` is intentionally NOT parsed here: spend policy has a
        // single authority (the ledger). A stray `image_spend` key in a loaded
        // document is ignored and can never authorize paid dispatch.
        // `image_generation` is redacted specially: a malformed value's serde /
        // validation error (`ImageGenerationConfigError` uses `{self:?}`, so
        // `MissingEndpoint("…")`, wrong-type `invalid type: string "…"`, etc.)
        // can embed attacker-supplied, credential-like strings. Never log or
        // surface the error itself — emit a stable field/path-only warning.
        if let Some(value) = raw.get("image_generation") {
            match serde_json::from_value::<crate::config::image_generation::ImageGenerationConfig>(
                value.clone(),
            ) {
                Ok(parsed) => cfg.image_generation = parsed,
                Err(_) => {
                    // Path-free AND error-free: the config path can itself carry
                    // a secret (token-named dir) and the serde error can embed
                    // credential-like values, so neither may reach the log.
                    tracing::warn!("ignored malformed `image_generation` configuration");
                    warnings.push(image_generation_malformed_warning());
                }
            }
        }
        parse_field!("image_sidecar", image_sidecar);
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
        parse_field!("computer_use", computer_use);
        parse_field!("computer_target", computer_target);
        parse_field!(
            "allow_computer_guidance_proposals",
            allow_computer_guidance_proposals
        );
        parse_field!("allow_remote_config", allow_remote_config);
        parse_field!("utility_model", utility_model);
        parse_field!("translation_model", translation_model);
        parse_field!("cheap_code", cheap_code);
        parse_field!("smart_code", smart_code);
        parse_field!("reasoning", reasoning);
        parse_field!("agent_chooses_subagent_model", agent_chooses_subagent_model);
        parse_field!("auto_title", auto_title);
        parse_field!(
            "auto_title_with_session_model",
            auto_title_with_session_model
        );
        parse_field!("skill_injection", skill_injection);
        parse_field!("predict_next_message_model", predict_next_message_model);
        parse_field!("harness_report_summarization", harness_report_summarization);
        parse_field!("compact_model", compact_model);
        parse_field!("btw_model", btw_model);
        parse_field!("embedding_model", embedding_model);
        if let Some(value) = raw.get("knowledgeBases") {
            match serde_json::from_value::<Vec<KnowledgeBaseRegistryEntry>>(value.clone()) {
                Ok(entries) if validate_knowledge_base_local_policy(&entries).is_ok() => {
                    cfg.knowledge_bases = entries;
                }
                Ok(_) | Err(_) => {
                    tracing::warn!("ignored invalid `knowledgeBases` policy");
                    warnings.push("ignored invalid `knowledgeBases` policy".to_string());
                }
            }
        }
        parse_field!("knowledge_inject_max_tokens", knowledge_inject_max_tokens);
        parse_field!("compact_prompt", compact_prompt);
        parse_field!("prompt_injection_guard", prompt_injection_guard);
        parse_field!("preflight", preflight);
        parse_field!("system_prompt", system_prompt);
        parse_field!("schedule", schedule);
        parse_field!("resourceScheduler", resource_scheduler);
        parse_field!("sandbox", sandbox);
        parse_field!("daemon", daemon);
        parse_field!("mediaResources", media_resources);
        parse_field!("delegation", delegation);
        parse_field!("deepthink", deepthink);
        parse_field!("review", review);
        parse_field!("goalSupervision", goal_supervision);
        parse_field!("lsp", lsp);
        parse_field!("data_syntax", data_syntax);
        parse_field!("loop_guard", loop_guard);
        parse_field!("maxPrimaryRounds", max_primary_rounds);
        parse_field!("dialog", dialog);
        parse_field!("skills", skills);
        if raw.contains_key("llm_mode") {
            cfg.removed_llm_mode = Some(
                raw.get("llm_mode")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("<non-string>")
                    .to_string(),
            );
            tracing::warn!(
                key = "llm_mode",
                "llm_mode is no longer used; posture now comes from agent definitions"
            );
            warnings.push(
                "llm_mode is no longer used; posture now comes from agent definitions".to_string(),
            );
        }
        if let Some(value) = raw.get("defaultPrimaryAgent") {
            match value.as_str() {
                Some("build") => cfg.default_primary_agent = DefaultPrimaryAgent::Build,
                Some("plan") => cfg.default_primary_agent = DefaultPrimaryAgent::Plan,
                Some(other) => {
                    cfg.default_primary_agent = DefaultPrimaryAgent::Build;
                    cfg.removed_default_primary_agent = Some(other.to_string());
                }
                None => match serde_json::from_value::<DefaultPrimaryAgent>(value.clone()) {
                    Ok(parsed) => cfg.default_primary_agent = parsed,
                    Err(error) => {
                        tracing::warn!(
                            path = %self.path.display(),
                            key = "defaultPrimaryAgent",
                            %error,
                            "skipping malformed extended config field"
                        );
                        warnings.push(format!(
                            "ignored malformed `{}` in {}",
                            "defaultPrimaryAgent",
                            self.path.display()
                        ));
                    }
                },
            }
        }
        parse_field!("translation", translation);
        parse_field!("sandboxEscalationEnabled", sandbox_escalation_enabled);
        parse_field!("sandbox_escalation_enabled", sandbox_escalation_enabled);
        parse_field!("defaultApprovalMode", default_approval_mode);
        parse_field!("sealedAcquisitionConsent", sealed_acquisition_consent);
        parse_field!("approvalPolicy", approval_policy);
        parse_field!("predictNextMessage", predict_next_message);
        parse_field!("shellCompression", shell_compression);
        parse_field!("commandResourceProfiles", command_resource_profiles);
        parse_field!("inlineThink", inline_think);
        parse_field!("hintToolCallCorrections", hint_tool_call_corrections);
        parse_field!("textEmbeddedRecovery", text_embedded_recovery);
        parse_field!("intelCentralityRanking", intel_centrality_ranking);
        parse_field!("queuedMessagesAsSteering", queued_messages_as_steering);
        parse_field!("intel", intel);

        migrate_legacy_web_tool_templates(&mut cfg);

        (cfg, warnings)
    }

    fn raw_for_layer_merge(&self, warnings: &mut Vec<String>) -> Value {
        let mut raw = self.raw.clone();
        if self.layer_is_remote() {
            // Defense-in-depth: a remote doc's stored `raw` is already stripped
            // at construction ([`Self::from_remote_layer`]), so this is
            // normally a no-op. Re-run it here so a remote layer can never
            // contribute an image-generation registry nor WIPE a lower local
            // one — `strip_remote_image_generation` removes the key from an
            // object layer and neutralizes a non-object raw (null/string/array)
            // that would otherwise clobber the accumulated local config via
            // `deep_merge_value`. Distinct from the malformed-*local* fail-closed
            // path below, which *replaces* with `{}` to wipe a broken local
            // layer.
            strip_remote_image_generation(&mut raw);
            strip_remote_image_sidecar(&mut raw);
        }
        strip_secret_store_key(&mut raw);
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
        remove_malformed!("response_metrics_tokenizer", TiktokenEncoding);
        remove_malformed!(
            "image_sidecar",
            crate::config::image_sidecar::SidecarSelectionConfig
        );
        // `image_spend` is deliberately not merged here: spend policy is never
        // a layered config value (its only authority is the ledger), so there
        // is nothing to sanitize or fail closed on at this boundary.
        if let Some(value) = obj.get("image_generation")
            && serde_json::from_value::<crate::config::image_generation::ImageGenerationConfig>(
                value.clone(),
            )
            .is_err()
        {
            // A present-but-invalid registry (missing endpoint for an enabled
            // target, dual defaults, workflow digest mismatch, dependent left
            // enabled after its endpoint/workflow was dropped, etc.) is an
            // explicit fail-closed layer. Replace with the empty-valid encoding
            // rather than removing the key, so a broken upper layer cannot
            // reveal and authorize a lower layer's registry. Record a redacted
            // (field-only) warning so
            // this fail-closed is surfaced through the layered load path instead
            // of happening silently. The log is path-free AND error-free: the
            // config path can itself carry a secret (token-named dir) and the
            // serde error can embed credential-like values, so neither may reach
            // the log or the returned warning.
            tracing::warn!("ignored malformed `image_generation` configuration");
            warnings.push(image_generation_malformed_warning());
            obj.insert("image_generation".into(), serde_json::json!({}));
        }
        remove_malformed!("tui", TuiConfig);
        remove_malformed!("computer_use", Option<ComputerUseMode>);
        remove_malformed!("computer_target", ComputerTarget);
        remove_malformed!("allow_computer_guidance_proposals", Option<bool>);
        if let Some(value) = obj.get("knowledgeBases") {
            match serde_json::from_value::<Vec<KnowledgeBaseRegistryEntry>>(value.clone()) {
                Ok(entries) if validate_knowledge_base_local_policy(&entries).is_ok() => {}
                Ok(_) | Err(_) => {
                    tracing::warn!("ignored invalid `knowledgeBases` policy");
                    warnings.push("ignored invalid `knowledgeBases` policy".to_string());
                    // An invalid upper registry must not reveal a lower one.
                    obj.insert("knowledgeBases".into(), serde_json::json!([]));
                }
            }
        }
        remove_malformed!("queuedMessagesAsSteering", bool);
        remove_malformed!("knowledge_inject_max_tokens", usize);
        remove_malformed!("sandboxEscalationEnabled", bool);
        remove_malformed!("sandbox_escalation_enabled", bool);
        remove_malformed!("prompt_injection_guard", PromptInjectionGuardConfig);
        remove_malformed!("approvalPolicy", ApprovalPolicyConfig);
        remove_malformed!("sandbox", SandboxConfig);
        remove_malformed!("review", ReviewConfig);
        remove_malformed!("goalSupervision", GoalSupervisionConfig);
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

    /// Remove one raw path while preserving every sibling mutation made by
    /// another config writer since this document was loaded.
    pub fn remove_raw_path_and_save(&mut self, path: &[&str]) -> Result<bool> {
        let _lock = crate::config::files::ConfigMutationLock::acquire(&self.path)?;
        let mut current = Self::load(&self.path)?;
        let removed = remove_raw_path(&mut current.raw, path);
        if removed {
            current.persist_raw_unlocked()?;
        }
        self.raw = current.raw;
        Ok(removed)
    }

    /// Render the result of removing one raw path without writing it. The
    /// daemon-owned settings writer uses this to preserve the document's
    /// unknown fields while keeping the actual filesystem mutation outside
    /// the TUI process.
    pub fn remove_raw_path_rendered(&mut self, path: &[&str]) -> Result<(bool, String)> {
        let _lock = crate::config::files::ConfigMutationLock::acquire(&self.path)?;
        let mut current = Self::load(&self.path)?;
        let removed = remove_raw_path(&mut current.raw, path);
        let rendered = current.render_raw()?;
        self.raw = current.raw;
        Ok((removed, rendered))
    }

    /// Render a typed update while preserving unknown raw keys. The caller is
    /// responsible for committing the returned document through its owner.
    pub fn rendered(&self, cfg: &ExtendedConfig) -> Result<String> {
        let originally_loaded = serde_json::to_value(self.config())
            .context("serializing originally loaded extended config")?;
        let mut current = Self::load(&self.path)?;
        current.merge_config_raw(&originally_loaded, cfg)?;
        current.render_raw()
    }

    fn render_raw(&self) -> Result<String> {
        let mut raw = self.raw.clone();
        strip_secret_store_key(&mut raw);
        let pretty = serde_json::to_string_pretty(&raw).context("serializing config.json")?;
        Ok(format!("{pretty}\n"))
    }

    fn persist_raw_unlocked(&self) -> Result<()> {
        let mut raw = self.raw.clone();
        strip_secret_store_key(&mut raw);
        let pretty = serde_json::to_string_pretty(&raw).context("serializing config.json")?;
        crate::config::files::atomic_write(&self.path, format!("{pretty}\n").as_bytes())
            .with_context(|| format!("writing {}", self.path.display()))?;
        Ok(())
    }

    /// Merge a typed [`ExtendedConfig`] back into the raw object and
    /// persist. Unknown keys are preserved, and absent default-valued
    /// fields stay absent so sparse project layers do not materialize
    /// inherited security policy by accident.
    pub fn write(&mut self, cfg: &ExtendedConfig) -> Result<()> {
        let originally_loaded = serde_json::to_value(self.config())
            .context("serializing originally loaded extended config")?;
        let _lock = crate::config::files::ConfigMutationLock::acquire(&self.path)?;
        let mut current = Self::load(&self.path)?;
        current.merge_config_raw(&originally_loaded, cfg)?;
        current.persist_raw_unlocked()?;
        self.raw = current.raw;
        Ok(())
    }

    fn merge_config_raw(&mut self, originally_loaded: &Value, cfg: &ExtendedConfig) -> Result<()> {
        let obj = self
            .raw
            .as_object_mut()
            .expect("config.json root is an object");
        let serialized = serde_json::to_value(cfg).context("serializing config")?;
        // Did the caller actually change `image_generation` relative to what it
        // loaded? Both `originally_loaded` and `serialized` always carry the
        // field (no `skip_serializing_if`), so this is a pure value comparison.
        let caller_changed_image_generation =
            originally_loaded.get("image_generation") != serialized.get("image_generation");
        if let (Value::Object(base), Value::Object(desired)) = (originally_loaded, &serialized) {
            apply_object_delta(obj, base, desired);
        }
        // `image_generation` is a closed, typed-only, ATOMIC registry, but
        // `apply_object_delta` above deep-merges nested objects and does not
        // consult `ATOMIC_CONFIG_VALUE_PATHS`. A recursive merge can leave stale
        // sub-arrays from the previous on-disk registry, yielding a persisted
        // registry that diverges from the typed `cfg`. Whole-replace the
        // freshly-reloaded raw with the typed value ONLY when either (a) this
        // caller actually changed the field — an atomic write, no deep-merge
        // hybrid — or (b) the reloaded raw is itself malformed/invalid
        // (decision 8: never persist an invalid registry). Otherwise the
        // reloaded value is a VALID registry this caller did not touch (it may
        // have been written concurrently by another writer between load and
        // this save) and must be preserved, not clobbered with this caller's
        // stale typed value. An ABSENT key stays absent, so sparse layers never
        // gain an `image_generation` they didn't have.
        if obj.contains_key("image_generation") {
            let reloaded_invalid = obj.get("image_generation").is_some_and(|value| {
                serde_json::from_value::<crate::config::image_generation::ImageGenerationConfig>(
                    value.clone(),
                )
                .is_err()
            });
            if caller_changed_image_generation || reloaded_invalid {
                obj.insert(
                    "image_generation".into(),
                    serde_json::to_value(&cfg.image_generation)
                        .context("serializing image_generation registry")?,
                );
            }
        }
        obj.remove("sandboxEscalationEnabled");
        obj.remove("llm_mode");
        obj.remove(&["trusted", "Only"].concat());
        obj.remove(&["trusted", "_only"].concat());
        Ok(())
    }
}

fn migrate_legacy_web_tool_templates(cfg: &mut ExtendedConfig) {
    migrate_legacy_web_tool_template(cfg, "webfetch", |web| &mut web.custom.fetch_command);
    migrate_legacy_web_tool_template(cfg, "websearch", |web| &mut web.custom.search_command);
}

fn migrate_legacy_web_tool_template(
    cfg: &mut ExtendedConfig,
    legacy_name: &str,
    target: impl FnOnce(&mut WebConfig) -> &mut Option<String>,
) {
    let Some(template) = cfg.tools.remove(legacy_name) else {
        return;
    };
    let destination = target(&mut cfg.web);
    if destination
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        return;
    }

    // Legacy web tool descriptions are intentionally not migrated. WebCustomConfig
    // fixes the tool contract by name; only the user-supplied command varies.
    *destination = Some(template.command);
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

fn apply_object_delta(
    current: &mut Map<String, Value>,
    base: &Map<String, Value>,
    desired: &Map<String, Value>,
) {
    let keys = base
        .keys()
        .chain(desired.keys())
        .collect::<std::collections::BTreeSet<_>>();
    for key in keys {
        match (base.get(key), desired.get(key)) {
            (Some(before), Some(after)) if before == after => {}
            (Some(Value::Object(before)), Some(Value::Object(after))) => {
                let target = current
                    .entry(key.clone())
                    .or_insert_with(|| Value::Object(before.clone()));
                if !target.is_object() {
                    *target = Value::Object(before.clone());
                }
                apply_object_delta(
                    target.as_object_mut().expect("object installed above"),
                    before,
                    after,
                );
            }
            (_, Some(after)) => {
                current.insert(key.clone(), after.clone());
            }
            (Some(_), None) => {
                current.remove(key);
            }
            (None, None) => unreachable!("key came from the union"),
        }
    }
}

#[cfg(test)]
mod tests;
