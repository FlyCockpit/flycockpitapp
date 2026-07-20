use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::agents::{AgentDef, AgentKind};
use crate::cli::AgentCommand;

pub async fn run(cmd: AgentCommand) -> Result<()> {
    match cmd {
        AgentCommand::Create {
            path,
            description,
            mode,
            tools,
            model,
        } => create(path, description, mode.unwrap_or_default(), tools, model),
        AgentCommand::List => list(),
    }
}

fn create(
    path: Option<PathBuf>,
    description: Option<String>,
    mode: crate::agents::AgentMode,
    tools: Option<String>,
    model: Option<String>,
) -> Result<()> {
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
    let tools = tools
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|values| !values.is_empty());
    let def = AgentDef {
        name: name.clone(),
        description,
        mode,
        model,
        temperature: None,
        tools,
        tool_tiers: std::collections::BTreeMap::new(),
        tool_descriptions: std::collections::BTreeMap::new(),
        scan_tool_results: None,
        permission: None,
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

    use crate::cli::{Cli, Command};

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
            mode: Some(crate::agents::AgentMode::Primary),
            tools: Some("read,bash".to_string()),
            model: Some("openai/gpt-5.5".to_string()),
        })
        .await
        .unwrap();

        let loaded = crate::agents::load_from_file(&path).unwrap();
        assert_eq!(loaded.name, "helper");
        assert_eq!(loaded.description, "Helps with tests");
        assert_eq!(loaded.mode, crate::agents::AgentMode::Primary);
        assert_eq!(loaded.tools.unwrap(), vec!["read", "bash"]);

        let cwd = temp.path();
        let listing = crate::agents::list_all(cwd)
            .into_iter()
            .find(|entry| entry.name == "helper")
            .expect("custom agent listed");
        assert!(matches!(listing.kind, AgentKind::Custom));
        assert!(listing.def.is_ok());
    }

    #[test]
    fn agent_create_cli_accepts_prompt_required_flags() {
        let cli = Cli::try_parse_from([
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
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Agent(AgentCommand::Create { .. }))
        ));
    }
}
