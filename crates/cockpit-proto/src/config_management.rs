//! Typed wire contract for daemon-owned Cockpit settings layers.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn deserialize_present_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

pub const OPAQUE_AUTHORITY_TOKEN_BYTES: usize = 64;
pub const REDACTED_DENYLIST_MASK: &str = "••••";

pub fn is_opaque_authority_token(value: &str) -> bool {
    value.len() == OPAQUE_AUTHORITY_TOKEN_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CockpitConfigLayer {
    HomeXdg,
    HomeDot,
    MachineLocal,
    Project,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigCommitStatus {
    Committed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigPublicationStatus {
    Published,
    Degraded,
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
    /// Exact typed paths authored by this layer. Values remain redacted; this
    /// list lets a client prove that an Unset removed authorship rather than
    /// merely observing the same effective default.
    pub authored_paths: Vec<Vec<String>>,
}

/// A path-scoped mutation of the daemon's authoritative typed settings
/// document. Paths contain unescaped JSON object keys (not a stringly JSON
/// pointer), which avoids ambiguous escaping and lets both peers apply the
/// exact same operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ExtendedConfigPathMutation {
    Set {
        path: Vec<String>,
        value: serde_json::Value,
    },
    Unset {
        path: Vec<String>,
    },
}

impl ExtendedConfigPathMutation {
    pub fn path(&self) -> &[String] {
        match self {
            Self::Set { path, .. } | Self::Unset { path } => path,
        }
    }
}

/// Exact typed operations to apply to one daemon-issued layer capability.
/// Unknown keys elsewhere in the raw document are preserved. The daemon
/// validates the complete result through `ExtendedConfig` and verifies that
/// each requested path is represented by that typed projection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedConfigPatch {
    pub operations: Vec<ExtendedConfigPathMutation>,
    /// Create the selected layer even when typed values are unchanged.
    pub materialize: bool,
    /// Complete desired denylist sequence. Existing occurrences can only be
    /// named by the opaque capability-bound ID returned in this snapshot;
    /// new literals never receive a client-selected identity.
    pub denylist: Vec<DesiredDenylistEntry>,
    /// Explicit authorization to replace/remove one redacted occurrence.
    /// Merely selecting its top-level field never grants this authority.
    pub redacted_mutations: Vec<RedactedOccurrenceMutation>,
}

impl ExtendedConfigPatch {
    /// Public correlation for the exact non-secret patch intent. Dedicated
    /// denylist/redacted secret literals are represented only by their
    /// operation and pointer/nonce so clients can bind a recovered receipt
    /// without learning or retaining the daemon's keyed durable digest.
    pub fn sanitized_intent_hash(&self) -> Result<String, serde_json::Error> {
        #[derive(Serialize)]
        struct Sanitized<'a> {
            operations: &'a [ExtendedConfigPathMutation],
            materialize: bool,
            denylist: Vec<SanitizedDenylist<'a>>,
            redacted_mutations: Vec<SanitizedRedacted<'a>>,
        }
        #[derive(Serialize)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        enum SanitizedDenylist<'a> {
            Existing { entry_id: &'a str },
            New { client_nonce: &'a str },
        }
        #[derive(Serialize)]
        #[serde(tag = "op", rename_all = "snake_case")]
        enum SanitizedRedacted<'a> {
            Set { pointer: &'a str },
            Unset { pointer: &'a str },
        }

        let denylist = self
            .denylist
            .iter()
            .map(|entry| match entry {
                DesiredDenylistEntry::Existing { entry_id } => {
                    SanitizedDenylist::Existing { entry_id }
                }
                DesiredDenylistEntry::New { client_nonce, .. } => {
                    SanitizedDenylist::New { client_nonce }
                }
            })
            .collect();
        let redacted_mutations = self
            .redacted_mutations
            .iter()
            .map(|mutation| match mutation {
                RedactedOccurrenceMutation::Set { pointer, .. } => {
                    SanitizedRedacted::Set { pointer }
                }
                RedactedOccurrenceMutation::Unset { pointer } => {
                    SanitizedRedacted::Unset { pointer }
                }
            })
            .collect();
        let bytes = serde_json::to_vec(&Sanitized {
            operations: &self.operations,
            materialize: self.materialize,
            denylist,
            redacted_mutations,
        })?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RedactedOccurrenceMutation {
    Set { pointer: String, value: String },
    Unset { pointer: String },
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
    pub fn from_json_key(key: &str) -> Option<Self> {
        const ALL: &[ExtendedConfigField] = &[
            ExtendedConfigField::ResponseMetricsTokenizer,
            ExtendedConfigField::ImageGeneration,
            ExtendedConfigField::Harnesses,
            ExtendedConfigField::AgentGuidanceFiles,
            ExtendedConfigField::Concurrency,
            ExtendedConfigField::AgentDirs,
            ExtendedConfigField::GitignoreAllow,
            ExtendedConfigField::Redact,
            ExtendedConfigField::Tui,
            ExtendedConfigField::Name,
            ExtendedConfigField::PackagesDirectory,
            ExtendedConfigField::Tools,
            ExtendedConfigField::Web,
            ExtendedConfigField::ComputerUse,
            ExtendedConfigField::AllowRemoteConfig,
            ExtendedConfigField::UtilityModel,
            ExtendedConfigField::TranslationModel,
            ExtendedConfigField::CheapCode,
            ExtendedConfigField::SmartCode,
            ExtendedConfigField::Reasoning,
            ExtendedConfigField::AgentChoosesSubagentModel,
            ExtendedConfigField::AutoTitle,
            ExtendedConfigField::SkillInjection,
            ExtendedConfigField::PredictNextMessageModel,
            ExtendedConfigField::HarnessReportSummarization,
            ExtendedConfigField::CompactModel,
            ExtendedConfigField::BtwModel,
            ExtendedConfigField::EmbeddingModel,
            ExtendedConfigField::ProjectKnowledge,
            ExtendedConfigField::KnowledgeInjectMaxTokens,
            ExtendedConfigField::CompactPrompt,
            ExtendedConfigField::PromptInjectionGuard,
            ExtendedConfigField::Preflight,
            ExtendedConfigField::SystemPrompt,
            ExtendedConfigField::Schedule,
            ExtendedConfigField::ResourceScheduler,
            ExtendedConfigField::Sandbox,
            ExtendedConfigField::Daemon,
            ExtendedConfigField::MediaResources,
            ExtendedConfigField::Retention,
            ExtendedConfigField::Delegation,
            ExtendedConfigField::Deepthink,
            ExtendedConfigField::Review,
            ExtendedConfigField::GoalSupervision,
            ExtendedConfigField::Lsp,
            ExtendedConfigField::DataSyntax,
            ExtendedConfigField::LoopGuard,
            ExtendedConfigField::MaxPrimaryRounds,
            ExtendedConfigField::Dialog,
            ExtendedConfigField::Skills,
            ExtendedConfigField::LlmMode,
            ExtendedConfigField::DefaultPrimaryAgent,
            ExtendedConfigField::RemovedDefaultPrimaryAgent,
            ExtendedConfigField::Translation,
            ExtendedConfigField::SandboxEscalationEnabled,
            ExtendedConfigField::DefaultApprovalMode,
            ExtendedConfigField::ApprovalPolicy,
            ExtendedConfigField::PredictNextMessage,
            ExtendedConfigField::ShellCompression,
            ExtendedConfigField::CommandResourceProfiles,
            ExtendedConfigField::InlineThink,
            ExtendedConfigField::HintToolCallCorrections,
            ExtendedConfigField::TextEmbeddedRecovery,
            ExtendedConfigField::IntelCentralityRanking,
        ];
        ALL.iter().copied().find(|field| field.json_key() == key)
    }

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
#[serde(tag = "source", rename_all = "snake_case")]
pub enum DesiredDenylistEntry {
    Existing {
        entry_id: String,
    },
    New {
        client_nonce: String,
        literal: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedDenylistEntry {
    pub entry_id: String,
    pub display_mask: String,
}

/// One occurrence in a committed denylist receipt. Existing occurrences echo
/// the exact authority ID consumed by the request; newly-created occurrences
/// echo their client nonce. In both cases `entry_id` is the exact refreshed
/// post-commit occurrence ID and no value-derived equality oracle is exposed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedDenylistEntry {
    pub entry_id: String,
    #[serde(deserialize_with = "deserialize_present_option")]
    pub consumed_entry_id: Option<String>,
    #[serde(deserialize_with = "deserialize_present_option")]
    pub client_nonce: Option<String>,
    pub display_mask: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret_patch(denylist_literal: &str, redacted_value: &str) -> ExtendedConfigPatch {
        ExtendedConfigPatch {
            operations: vec![ExtendedConfigPathMutation::Set {
                path: vec!["tui".into(), "mouse".into()],
                value: serde_json::json!(true),
            }],
            materialize: true,
            denylist: vec![DesiredDenylistEntry::New {
                client_nonce: "nonce-1".into(),
                literal: denylist_literal.into(),
            }],
            redacted_mutations: vec![RedactedOccurrenceMutation::Set {
                pointer: "/provider/token".into(),
                value: redacted_value.into(),
            }],
        }
    }

    #[test]
    fn sanitized_patch_intent_excludes_secret_literals_but_binds_public_shape() {
        let first = secret_patch("secret-a", "token-a");
        let second = secret_patch("secret-b", "token-b");
        assert_eq!(
            first.sanitized_intent_hash().unwrap(),
            second.sanitized_intent_hash().unwrap()
        );

        let mut different_target = second;
        different_target.redacted_mutations = vec![RedactedOccurrenceMutation::Set {
            pointer: "/provider/other-token".into(),
            value: "token-b".into(),
        }];
        assert_ne!(
            first.sanitized_intent_hash().unwrap(),
            different_target.sanitized_intent_hash().unwrap()
        );
    }
}
