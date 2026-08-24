//! Typed wire contract for daemon-owned Cockpit settings layers.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CockpitConfigLayer {
    HomeXdg,
    HomeDot,
    MachineLocal,
    Project,
}

/// A daemon-discovered settings layer. `layer_id` is an ephemeral,
/// occurrence-bound capability; clients never nominate a path or ancestry
/// depth for a mutation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedConfigLayerSnapshot {
    pub layer_id: String,
    pub kind: CockpitConfigLayer,
    /// Presentation only. This path is never accepted back as authority.
    pub display_path: String,
    pub config: Box<cockpit_config::config::extended::ExtendedConfig>,
    pub denylist: Vec<RedactedDenylistEntry>,
    pub revision: String,
}

/// The complete typed candidate plus an explicit allowlist of fields to copy
/// into the authoritative raw document. A client cannot mutate an unknown key:
/// values are deserialized through `ExtendedConfig` and only named fields are
/// selected. Secret-bearing denylist entries have a separate opaque-ID API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedConfigPatch {
    pub candidate: cockpit_config::config::extended::ExtendedConfig,
    /// Selected fields whose serialized value is present in `candidate`.
    pub fields: Vec<ExtendedConfigField>,
    /// Selected optional/default-valued fields that must be removed from this
    /// layer. This distinguishes an intentional clear from serde's
    /// `skip_serializing_if` omission.
    #[serde(default)]
    pub unset_fields: Vec<ExtendedConfigField>,
    /// Create the selected layer even when typed values are unchanged.
    #[serde(default)]
    pub materialize: bool,
    #[serde(default)]
    pub denylist: Vec<DenylistMutation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtendedConfigField {
    ResponseMetricsTokenizer,
    ImageGeneration,
    Harnesses,
    AgentGuidanceFiles,
    Concurrency,
    AgentDirs,
    GitignoreAllow,
    Redact,
    Tui,
    Name,
    PackagesDirectory,
    Tools,
    Web,
    ComputerUse,
    AllowRemoteConfig,
    UtilityModel,
    TranslationModel,
    CheapCode,
    SmartCode,
    Reasoning,
    AgentChoosesSubagentModel,
    AutoTitle,
    SkillInjection,
    PredictNextMessageModel,
    HarnessReportSummarization,
    CompactModel,
    BtwModel,
    EmbeddingModel,
    ProjectKnowledge,
    KnowledgeInjectMaxTokens,
    CompactPrompt,
    PromptInjectionGuard,
    Preflight,
    SystemPrompt,
    Schedule,
    ResourceScheduler,
    Sandbox,
    Daemon,
    MediaResources,
    Retention,
    Delegation,
    Deepthink,
    Review,
    GoalSupervision,
    Lsp,
    DataSyntax,
    LoopGuard,
    MaxPrimaryRounds,
    Dialog,
    Skills,
    LlmMode,
    DefaultPrimaryAgent,
    RemovedDefaultPrimaryAgent,
    Translation,
    SandboxEscalationEnabled,
    DefaultApprovalMode,
    ApprovalPolicy,
    PredictNextMessage,
    ShellCompression,
    CommandResourceProfiles,
    InlineThink,
    HintToolCallCorrections,
    TextEmbeddedRecovery,
    IntelCentralityRanking,
}

impl ExtendedConfigField {
    pub fn json_key(self) -> &'static str {
        match self {
            Self::ResponseMetricsTokenizer => "response_metrics_tokenizer",
            Self::ImageGeneration => "image_generation",
            Self::Harnesses => "harnesses",
            Self::AgentGuidanceFiles => "agent_guidance_files",
            Self::Concurrency => "concurrency",
            Self::AgentDirs => "agent_dirs",
            Self::GitignoreAllow => "gitignore_allow",
            Self::Redact => "redact",
            Self::Tui => "tui",
            Self::Name => "name",
            Self::PackagesDirectory => "packages_directory",
            Self::Tools => "tools",
            Self::Web => "web",
            Self::ComputerUse => "computer_use",
            Self::AllowRemoteConfig => "allow_remote_config",
            Self::UtilityModel => "utility_model",
            Self::TranslationModel => "translation_model",
            Self::CheapCode => "cheap_code",
            Self::SmartCode => "smart_code",
            Self::Reasoning => "reasoning",
            Self::AgentChoosesSubagentModel => "agent_chooses_subagent_model",
            Self::AutoTitle => "auto_title",
            Self::SkillInjection => "skill_injection",
            Self::PredictNextMessageModel => "predict_next_message_model",
            Self::HarnessReportSummarization => "harness_report_summarization",
            Self::CompactModel => "compact_model",
            Self::BtwModel => "btw_model",
            Self::EmbeddingModel => "embedding_model",
            Self::ProjectKnowledge => "project_knowledge",
            Self::KnowledgeInjectMaxTokens => "knowledge_inject_max_tokens",
            Self::CompactPrompt => "compact_prompt",
            Self::PromptInjectionGuard => "prompt_injection_guard",
            Self::Preflight => "preflight",
            Self::SystemPrompt => "system_prompt",
            Self::Schedule => "schedule",
            Self::ResourceScheduler => "resource_scheduler",
            Self::Sandbox => "sandbox",
            Self::Daemon => "daemon",
            Self::MediaResources => "media_resources",
            Self::Retention => "retention",
            Self::Delegation => "delegation",
            Self::Deepthink => "deepthink",
            Self::Review => "review",
            Self::GoalSupervision => "goal_supervision",
            Self::Lsp => "lsp",
            Self::DataSyntax => "data_syntax",
            Self::LoopGuard => "loop_guard",
            Self::MaxPrimaryRounds => "max_primary_rounds",
            Self::Dialog => "dialog",
            Self::Skills => "skills",
            Self::LlmMode => "llm_mode",
            Self::DefaultPrimaryAgent => "default_primary_agent",
            Self::RemovedDefaultPrimaryAgent => "removed_default_primary_agent",
            Self::Translation => "translation",
            Self::SandboxEscalationEnabled => "sandbox_escalation_enabled",
            Self::DefaultApprovalMode => "default_approval_mode",
            Self::ApprovalPolicy => "approval_policy",
            Self::PredictNextMessage => "predict_next_message",
            Self::ShellCompression => "shell_compression",
            Self::CommandResourceProfiles => "command_resource_profiles",
            Self::InlineThink => "inline_think",
            Self::HintToolCallCorrections => "hint_tool_call_corrections",
            Self::TextEmbeddedRecovery => "text_embedded_recovery",
            Self::IntelCentralityRanking => "intel_centrality_ranking",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum DenylistMutation {
    Add {
        value: String,
        after_id: Option<String>,
    },
    Update {
        entry_id: String,
        value: String,
    },
    Remove {
        entry_id: String,
    },
    Move {
        entry_id: String,
        after_id: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedDenylistEntry {
    pub entry_id: String,
    pub fingerprint: String,
    pub display_mask: String,
}
