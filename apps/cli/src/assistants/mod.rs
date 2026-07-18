//! Assistant definitions and persistence helpers.
//!
//! An assistant is an entity wrapper around an agent-shaped markdown
//! definition stored at `<assistant-home>/assistant.md`. The markdown parser is
//! deliberately the same parser used for agents.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::agents::{AgentDef, AgentMode};
use crate::db::Db;
use crate::db::assistants::AssistantRow;
use crate::wizard::{
    SelectOption, StepDescriptor, StepKind, WizardAnswer, WizardDescriptor, WizardRun, WritePolicy,
};

pub const ASSISTANT_WIZARD_ID: &str = "assistant";

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
    pub mode: AgentMode,
    pub tools: Option<Vec<String>>,
    pub model: Option<String>,
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
    let agent = crate::agents::load_named_from_file(&path, name)
        .with_context(|| format!("loading assistant definition {}", path.display()))?;
    Ok(AssistantDef {
        name: name.to_string(),
        description: agent.description.clone(),
        home_dir: home_dir.to_path_buf(),
        agent,
    })
}

pub fn load_from_row(row: &AssistantRow) -> Result<AssistantDef> {
    load_from_home(&row.name, Path::new(&row.home_dir))
}

pub fn create_assistant(db: &Db, spec: CreateAssistantSpec) -> Result<AssistantRow> {
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
        mode: spec.mode,
        model: spec.model,
        temperature: None,
        tools: spec.tools,
        tool_descriptions: std::collections::BTreeMap::new(),
        scan_tool_results: None,
        permission: None,
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
}

pub fn descriptor() -> WizardDescriptor {
    WizardDescriptor {
        id: ASSISTANT_WIZARD_ID,
        title: "Create assistant",
        description: "Create a persistent assistant identity backed by an agent definition.",
        write_policy: WritePolicy::CommitAtEnd,
        steps: vec![
            StepDescriptor {
                id: "description",
                prompt: "Assistant description",
                help: "Short human-readable purpose for lists and selection surfaces.",
                kind: StepKind::Text,
                default_answer: None,
                prefill: None,
                validate: Some(non_empty_text),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "mode",
                prompt: "Assistant reachability",
                help: "Primary assistants can own chat; subagents can only receive delegated tasks.",
                kind: StepKind::Select {
                    options: vec![
                        SelectOption {
                            id: "primary",
                            label: "Primary",
                            description: "Owns top-level chats.",
                        },
                        SelectOption {
                            id: "all",
                            label: "Primary + subagent",
                            description: "Can own chats and receive delegated tasks.",
                        },
                        SelectOption {
                            id: "subagent",
                            label: "Subagent",
                            description: "Only receives delegated tasks.",
                        },
                    ],
                },
                default_answer: Some(WizardAnswer::Select("primary".to_string())),
                prefill: None,
                validate: None,
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "model",
                prompt: "Model override (blank to inherit)",
                help: "Optional provider/model override.",
                kind: StepKind::Text,
                default_answer: Some(WizardAnswer::Text(String::new())),
                prefill: None,
                validate: None,
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "tools",
                prompt: "Tool grants (comma-separated, blank to inherit)",
                help: "Optional list such as bash,read.",
                kind: StepKind::Text,
                default_answer: Some(WizardAnswer::Text(String::new())),
                prefill: None,
                validate: None,
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "prompt",
                prompt: "System prompt",
                help: "The assistant's agent prompt body.",
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
    let mode = match select_answer(run, "mode").as_deref() {
        Some("all") => AgentMode::All,
        Some("subagent") => AgentMode::Subagent,
        _ => AgentMode::Primary,
    };
    let model = text_answer(run, "model").and_then(non_blank);
    let tools = text_answer(run, "tools")
        .and_then(non_blank)
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|tools| !tools.is_empty());
    let prompt = text_answer(run, "prompt").context("assistant prompt missing")?;
    Ok(CreateAssistantSpec {
        name: name.to_string(),
        description,
        mode,
        tools,
        model,
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

fn select_answer(run: &WizardRun, step: &str) -> Option<String> {
    match run.answer(step) {
        Some(WizardAnswer::Select(value)) => Some(value.clone()),
        _ => None,
    }
}

fn non_blank(value: String) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    crate::intel::hex_lower(&Sha256::digest(bytes))
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
            "---\ndescription: Helps with tests\nmode: primary\ntools: [read]\n---\n\nStay focused.\n",
        )
        .unwrap();

        let def = load_from_home("my-helper", &home).unwrap();

        assert_eq!(def.name, "my-helper");
        assert_eq!(def.description, "Helps with tests");
        assert_eq!(def.agent.name, "my-helper");
        assert_eq!(def.agent.prompt, "Stay focused.");
        assert_eq!(def.agent.tools.as_deref(), Some(&["read".to_string()][..]));
    }
}
