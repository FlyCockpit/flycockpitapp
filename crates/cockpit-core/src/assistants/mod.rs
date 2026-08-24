//! Assistant definitions and persistence helpers.
//!
//! An assistant is an entity wrapper around an agent-shaped markdown
//! definition stored at `<assistant-home>/assistant.md`. The markdown parser is
//! deliberately the same parser used for agents.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::agents::{
    AgentDef, AgentMode, ExecutionKind, ModelCapability, ModelLocality, ModelSlot, VnextAgentDef,
};
use crate::db::Db;
use crate::db::assistants::AssistantRow;
use crate::wizard::{
    StepDescriptor, StepKind, WizardAnswer, WizardDescriptor, WizardRun, WritePolicy,
};

pub const ASSISTANT_WIZARD_ID: &str = "assistant";
#[cfg(test)]
pub(crate) const VALID_ASSISTANT_CONTENT_HASH_FIXTURE: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

pub mod identity;
pub mod self_improvement;

#[derive(Debug, Clone)]
pub struct AssistantDef {
    pub name: String,
    pub description: String,
    pub home_dir: PathBuf,
    pub agent: AgentDef,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssistantConfig {
    /// Daemon-owned installation identity.  This is deliberately distinct
    /// from the editable assistant display name and is the sole source of
    /// the `local/<UUID>` vNext publisher identity.
    #[serde(rename = "installationId")]
    pub installation_id: Uuid,
    #[serde(default)]
    pub agent_source: String,
    #[serde(default)]
    pub soul_edit_mode: identity::SoulEditMode,
    #[serde(default = "identity::default_identity_max_tokens")]
    pub identity_max_tokens: usize,
    #[serde(default)]
    pub soul_hash: Option<String>,
    #[serde(default)]
    pub user_hash: Option<String>,
    #[serde(default = "self_improvement::default_skill_review_interval")]
    pub skill_review_interval: u32,
}

impl Default for AssistantConfig {
    fn default() -> Self {
        Self {
            installation_id: Uuid::nil(),
            agent_source: String::new(),
            soul_edit_mode: identity::SoulEditMode::default(),
            identity_max_tokens: identity::default_identity_max_tokens(),
            soul_hash: None,
            user_hash: None,
            skill_review_interval: self_improvement::DEFAULT_SKILL_REVIEW_INTERVAL,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CreateAssistantSpec {
    pub name: String,
    pub description: String,
    pub prompt: String,
    pub home_dir: PathBuf,
}

pub fn validate_assistant_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("assistant name is required");
    }
    let valid = name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && name
            .bytes()
            .last()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    if !valid || name.contains("--") {
        bail!("assistant name `{name}` must be kebab-case");
    }
    Ok(())
}

pub fn default_home_dir(name: &str) -> Result<PathBuf> {
    Ok(crate::config::resolve::cockpit_data_dir()?
        .join("assistants")
        .join(name))
}

pub fn assistant_definition_path(home_dir: &Path) -> PathBuf {
    home_dir.join("assistant.md")
}

pub fn load_from_home(name: &str, home_dir: &Path) -> Result<AssistantDef> {
    validate_assistant_name(name)?;
    let path = assistant_definition_path(home_dir);
    let agent = crate::agents::load_daemon_local_named_from_file(&path, name)
        .with_context(|| format!("loading assistant definition {}", path.display()))?;
    Ok(AssistantDef {
        name: name.to_string(),
        description: agent.description.clone(),
        home_dir: home_dir.to_path_buf(),
        agent,
    })
}

pub fn load_from_row(row: &AssistantRow) -> Result<AssistantDef> {
    let config: AssistantConfig = serde_json::from_str(&row.config_json)
        .with_context(|| format!("parsing assistant config for `{}`", row.name))?;
    if config.installation_id.is_nil() {
        bail!(
            "assistant `{}` has no daemon-owned installation ID",
            row.name
        );
    }
    let definition = load_from_home(&row.name, Path::new(&row.home_dir))?;
    let expected_agent_id = format!("local/{}", config.installation_id);
    if definition
        .agent
        .vnext
        .as_ref()
        .map(|vnext| vnext.agent_id.as_str())
        != Some(expected_agent_id.as_str())
    {
        bail!(
            "assistant `{}` definition identity does not match its daemon-owned installation ID",
            row.name
        );
    }
    Ok(definition)
}

pub async fn create_assistant(db: &Db, spec: CreateAssistantSpec) -> Result<AssistantRow> {
    create_assistant_with_installation_id(db, spec, Uuid::new_v4()).await
}

/// Create an assistant using a caller-supplied installation identity.
///
/// The normal daemon-owned creation path uses [`create_assistant`], which
/// mints a fresh UUID. This explicit form is for flows that must write the
/// definition and registry configuration from one preallocated identity.
pub async fn create_assistant_with_installation_id(
    db: &Db,
    spec: CreateAssistantSpec,
    installation_id: Uuid,
) -> Result<AssistantRow> {
    validate_assistant_name(&spec.name)?;
    if spec.description.trim().is_empty() {
        bail!("assistant description is required");
    }
    if spec.prompt.trim().is_empty() {
        bail!("assistant prompt is required");
    }
    std::fs::create_dir_all(&spec.home_dir)
        .with_context(|| format!("creating assistant home {}", spec.home_dir.display()))?;
    let path = assistant_definition_path(&spec.home_dir);
    let agent = AgentDef {
        name: spec.name.clone(),
        description: spec.description,
        // These retained in-memory fields are ignored by schemaVersion 2.
        // They cannot be configured from the assistant specification.
        mode: AgentMode::Primary,
        model: None,
        temperature: None,
        tools: None,
        tool_tiers: std::collections::BTreeMap::new(),
        tool_descriptions: std::collections::BTreeMap::new(),
        scan_tool_results: None,
        goal_supervision: crate::agents::GoalSettingsOverride::default(),
        permission: None,
        fork_eligible: false,
        // Assistant homes are daemon-owned definition locations, so they are
        // the sole constructor allowed to use the local publisher. Tool/model
        // selections from the legacy wizard remain host-side setup inputs and
        // are intentionally absent from the serialized v2 definition.
        vnext: Some(vnext_for_private_assistant(installation_id)),
        prompt: spec.prompt,
        prompt_variants: std::collections::HashMap::new(),
        source: path.clone(),
    };
    crate::agents::validate_invariants(&agent)?;
    let markdown = agent.to_markdown()?;
    std::fs::write(&path, &markdown)
        .with_context(|| format!("writing assistant definition {}", path.display()))?;
    identity::seed_identity_files(&spec.home_dir)?;
    let config = AssistantConfig {
        installation_id,
        agent_source: path.to_string_lossy().into_owned(),
        soul_hash: identity::hash_optional_file(&identity::soul_path(&spec.home_dir))?,
        user_hash: identity::hash_optional_file(&identity::user_path(&spec.home_dir))?,
        ..AssistantConfig::default()
    };
    let config_json = serde_json::to_string(&config)?;
    let content_hash = sha256_hex(markdown.as_bytes());
    db.upsert_assistant(
        &spec.name,
        &spec.home_dir.to_string_lossy(),
        &config_json,
        &content_hash,
    )
    .await
}

/// The sole daemon-owned v2 template for private assistants.  CLI-side
/// creation reuses it so both persistence paths produce the same provenance
/// and never serialize the retired tool/model/mode contract.
pub fn vnext_for_private_assistant(installation_id: Uuid) -> VnextAgentDef {
    VnextAgentDef {
        schema_version: crate::agents::SCHEMA_VERSION,
        agent_id: format!("local/{installation_id}"),
        execution_kind: ExecutionKind::Assistant,
        model_slots: std::collections::BTreeMap::from([(
            "primary".to_string(),
            ModelSlot {
                purpose: "Primary model for this private assistant.".to_string(),
                min_context_tokens: 1,
                required_capabilities: vec![ModelCapability::TextGeneration],
                locality: ModelLocality::Any,
                allow_default_fallback: true,
                suggested_models: Vec::new(),
            },
        )]),
        delegation: Default::default(),
        questions: None,
        verification: None,
    }
}

/// Snapshot every persisted private-assistant definition into the session's
/// daemon-owned UUID resolver.  Definitions are loaded once under the trusted
/// assistant-home boundary and then used directly for every child launch.
pub async fn local_installation_resolver(
    db: &Db,
) -> Result<crate::agents::LocalInstallationResolver> {
    let mut definitions = std::collections::BTreeMap::new();
    for row in db.list_assistants().await? {
        let config: AssistantConfig = serde_json::from_str(&row.config_json)
            .with_context(|| format!("parsing assistant config for `{}`", row.name))?;
        if config.installation_id.is_nil() {
            bail!(
                "assistant `{}` has no daemon-owned installation ID",
                row.name
            );
        }
        let definition = load_from_row(&row)?.agent;
        if definitions
            .insert(config.installation_id, definition)
            .is_some()
        {
            bail!(
                "multiple persisted assistants claim daemon-local installation ID `{}`",
                config.installation_id
            );
        }
    }
    crate::agents::LocalInstallationResolver::from_bound_definitions(definitions)
}

pub fn descriptor() -> WizardDescriptor {
    WizardDescriptor {
        id: ASSISTANT_WIZARD_ID,
        title: "Create assistant",
        description: "Create a persistent assistant identity backed by an agent definition.",
        write_policy: WritePolicy::CommitAtEnd,
        model_context: None,
        steps: vec![
            StepDescriptor {
                id: "description",
                prompt: "Assistant description",
                help: "Short human-readable purpose for lists and selection surfaces.",
                help_hook: None,
                kind: StepKind::Text,
                default_answer: None,
                prefill: None,
                validate: Some(non_empty_text),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "prompt",
                prompt: "System prompt",
                help: "The assistant's agent prompt body.",
                help_hook: None,
                kind: StepKind::Text,
                default_answer: Some(WizardAnswer::Text(
                    "You are a persistent Cockpit assistant.".to_string(),
                )),
                prefill: None,
                validate: Some(non_empty_text),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "save",
                prompt: "Save assistant",
                help: "Writes assistant.md and records the assistant row.",
                help_hook: None,
                kind: StepKind::Action {
                    progress: "Saving assistant...",
                },
                default_answer: None,
                prefill: None,
                validate: None,
                write: None,
                branch: None,
            },
        ],
    }
}

pub fn spec_from_wizard(
    name: &str,
    home_dir: PathBuf,
    run: &WizardRun,
) -> Result<CreateAssistantSpec> {
    validate_assistant_name(name)?;
    let description = text_answer(run, "description").context("assistant description missing")?;
    let prompt = text_answer(run, "prompt").context("assistant prompt missing")?;
    Ok(CreateAssistantSpec {
        name: name.to_string(),
        description,
        prompt,
        home_dir,
    })
}

fn non_empty_text(_: &WizardRun, answer: &WizardAnswer) -> std::result::Result<(), String> {
    match answer {
        WizardAnswer::Text(value) if !value.trim().is_empty() => Ok(()),
        _ => Err("value is required".to_string()),
    }
}

fn text_answer(run: &WizardRun, step: &str) -> Option<String> {
    match run.answer(step) {
        Some(WizardAnswer::Text(value)) => Some(value.clone()),
        _ => None,
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    crate::intel::hex_lower(&Sha256::digest(bytes))
}

pub fn markdown_content_hash(markdown: &str) -> String {
    sha256_hex(markdown.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assistant_def_parses_via_agent_parser() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("my-helper");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            assistant_definition_path(&home),
            "---\nagentId: local/00000000-0000-0000-0000-000000000001\ndescription: Helps with tests\nexecutionKind: assistant\nmodelSlots:\n  primary:\n    allowDefaultFallback: true\n    locality: any\n    minContextTokens: 1\n    purpose: Primary model\n    requiredCapabilities: [text_generation]\nschemaVersion: 2\n---\n\nStay focused.\n",
        )
        .unwrap();

        let def = load_from_home("my-helper", &home).unwrap();

        assert_eq!(def.name, "my-helper");
        assert_eq!(def.description, "Helps with tests");
        assert_eq!(def.agent.name, "my-helper");
        assert_eq!(def.agent.prompt, "Stay focused.");
        assert_eq!(
            def.agent.vnext.as_ref().map(|v| v.execution_kind),
            Some(ExecutionKind::Assistant)
        );
        assert!(def.agent.tools.is_none());
    }
}
