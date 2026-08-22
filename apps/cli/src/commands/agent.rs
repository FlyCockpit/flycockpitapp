use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::agents::{AgentDef, AgentKind};
use crate::cli::AgentCommand;
use cockpit_core::agents::{
    DelegationPolicy, ExecutionKind, ModelCapability, ModelLocality, ModelSlot, VnextAgentDef,
};

pub async fn run(cmd: AgentCommand) -> Result<()> {
    match cmd {
        AgentCommand::Create { path, description } => create(path, description),
        AgentCommand::List => list(),
    }
}

fn create(path: Option<PathBuf>, description: Option<String>) -> Result<()> {
    let path =
        path.ok_or_else(|| anyhow::anyhow!("--path is required for `cockpit agent create`"))?;
    if path.is_dir() {
        bail!("--path must name the agent markdown file, not a directory");
    }
    if path.extension().and_then(|ext| ext.to_str()) != Some("md") {
        bail!("--path must end in .md");
    }
    let name = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("--path must have a usable file stem"))?
        .to_string();
    let description = description.unwrap_or_else(|| format!("Custom agent `{name}`"));
    let def = AgentDef {
        name: name.clone(),
        description,
        mode: crate::agents::AgentMode::default(),
        model: None,
        temperature: None,
        tools: None,
        tool_tiers: std::collections::BTreeMap::new(),
        tool_descriptions: std::collections::BTreeMap::new(),
        scan_tool_results: None,
        goal_supervision: cockpit_core::agents::GoalSettingsOverride::default(),
        permission: None,
        fork_eligible: false,
        vnext: Some(VnextAgentDef {
            schema_version: cockpit_core::agents::SCHEMA_VERSION,
            agent_id: format!("authored/{name}"),
            execution_kind: ExecutionKind::Coding,
            model_slots: std::collections::BTreeMap::from([(
                "primary".to_string(),
                ModelSlot {
                    purpose: "Primary model for this workspace agent.".to_string(),
                    min_context_tokens: 1,
                    required_capabilities: vec![ModelCapability::TextGeneration],
                    locality: ModelLocality::Any,
                    allow_default_fallback: true,
                    suggested_models: Vec::new(),
                },
            )]),
            delegation: DelegationPolicy::default(),
            questions: None,
            verification: None,
        }),
        prompt: format!("You are the `{name}` Cockpit agent."),
        prompt_variants: std::collections::HashMap::new(),
        source: path.clone(),
    };
    crate::agents::validate_invariants(&def)?;
    let markdown = def.to_markdown()?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating agents dir {}", parent.display()))?;
    }
    std::fs::write(&path, markdown).with_context(|| format!("writing agent {}", path.display()))?;
    let loaded = crate::agents::load_from_file(&path)?;
    println!("created agent `{}` at {}", loaded.name, path.display());
    Ok(())
}

fn list() -> Result<()> {
    let cwd = std::env::current_dir().context("resolving cwd")?;
    for listing in crate::agents::list_all(&cwd) {
        let kind = match listing.kind {
            AgentKind::Builtin { overridden } if overridden => "builtin override",
            AgentKind::Builtin { .. } => "builtin",
            AgentKind::Custom => "custom",
        };
        match listing.def {
            Ok(def) => println!("{}\t{}\t{}", listing.name, kind, def.description),
            Err(error) => println!("{}\t{}\t<invalid: {}>", listing.name, kind, error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    use crate::cli::Cli;

    #[tokio::test]
    async fn agent_create_then_list() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp
            .path()
            .join(".cockpit")
            .join("agents")
            .join("helper.md");
        run(AgentCommand::Create {
            path: Some(path.clone()),
            description: Some("Helps with tests".to_string()),
        })
        .await
        .unwrap();

        let loaded = crate::agents::load_from_file(&path).unwrap();
        assert_eq!(loaded.name, "helper");
        assert_eq!(loaded.description, "Helps with tests");
        assert!(loaded.vnext.is_some());
        assert!(loaded.tools.is_none());

        let cwd = temp.path();
        let policy = cockpit_config::trust::WorkspaceTrustPolicy {
            root: cockpit_config::trust::resolve_trust_root(cwd).unwrap(),
            mode: cockpit_db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        let listing = cockpit_config::trust::with_workspace_trust_policy(policy, || {
            crate::agents::list_all(cwd)
                .into_iter()
                .find(|entry| entry.name == "helper")
                .expect("custom agent listed")
        });
        assert!(matches!(listing.kind, AgentKind::Custom));
        assert!(listing.def.is_ok());
    }

    #[test]
    fn agent_create_cli_rejects_removed_legacy_authority_flags() {
        let error = Cli::try_parse_from([
            "cockpit",
            "agent",
            "create",
            "--path",
            "helper.md",
            "--description",
            "Helps",
            "--mode",
            "primary",
            "--tools",
            "read",
            "--model",
            "openai/gpt-5.5",
        ])
        .unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }
}
