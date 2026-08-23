use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::cli::AgentCommand;
use crate::daemon::client::ensure_persistent_daemon;
use crate::daemon::proto::{
    AGENT_INSTALLATION_DTO_VERSION, AgentInstallationBeginV1, AgentInstallationOperationKind,
    AgentInstallationReadV1, AgentInstallationResultV1, AgentInstallationScopeWire,
    AgentInstallationSubmitChoiceV1, Request, Response,
};

pub async fn run(cmd: AgentCommand) -> Result<()> {
    match cmd {
        AgentCommand::Install {
            source,
            replace,
            workspace,
            shared,
            operation_key,
            yes,
        } => {
            begin(
                source,
                AgentInstallationOperationKind::Install,
                replace,
                None,
                workspace,
                shared,
                operation_key,
                yes,
            )
            .await
        }
        AgentCommand::Update {
            source,
            replace,
            workspace,
            shared,
            operation_key,
            yes,
        } => {
            begin(
                source,
                AgentInstallationOperationKind::Update,
                replace,
                None,
                workspace,
                shared,
                operation_key,
                yes,
            )
            .await
        }
        AgentCommand::Bind {
            installation_id,
            slot,
            workspace,
            shared,
            operation_key,
            yes,
        } => {
            begin(
                installation_id,
                AgentInstallationOperationKind::Bind,
                false,
                Some(slot),
                workspace,
                shared,
                operation_key,
                yes,
            )
            .await
        }
        AgentCommand::SubmitChoice {
            continuation_token,
            choice_id,
            defer,
        } => submit_choice(continuation_token, choice_id, defer).await,
        AgentCommand::Inspect {
            installation_id,
            workspace,
            shared,
        } => inspect(installation_id, workspace, shared).await,
        AgentCommand::Create {
            path,
            description,
            execution_kind,
            primary_slot,
            workspace,
            shared,
            operation_key,
        } => {
            create(
                path,
                description,
                execution_kind,
                primary_slot,
                workspace,
                shared,
                operation_key,
            )
            .await
        }
        AgentCommand::List { workspace, shared } => list(workspace, shared).await,
    }
}

async fn submit_choice(
    continuation_token: String,
    choice_id: Option<String>,
    defer: bool,
) -> Result<()> {
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for agent choice")?;
    let response = daemon
        .client
        .request(Request::AgentInstallationSubmitChoice(
            AgentInstallationSubmitChoiceV1 {
                dto_version: AGENT_INSTALLATION_DTO_VERSION,
                continuation_token,
                choice_id,
                defer,
            },
        ))
        .await
        .context("sending agent choice to daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected agent choice: {error}"))?;
    match response {
        Response::AgentInstallation(AgentInstallationResultV1::Receipt {
            status,
            installation_id,
            ..
        }) => println!(
            "agent choice completed: {status:?}{}",
            installation_id
                .map(|id| format!(" ({id})"))
                .unwrap_or_default()
        ),
        Response::AgentInstallation(AgentInstallationResultV1::Error { error }) => {
            bail!("agent choice refused: {:?}", error.code)
        }
        _ => bail!("daemon returned unexpected response to agent choice"),
    }
    Ok(())
}

async fn begin(
    source_locator: String,
    operation: AgentInstallationOperationKind,
    replace_acknowledged: bool,
    requested_slot: Option<String>,
    workspace: Option<PathBuf>,
    shared: bool,
    operation_key: Option<String>,
    yes: bool,
) -> Result<()> {
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for agent operation")?;
    let response = daemon
        .client
        .request(Request::AgentInstallationBegin(AgentInstallationBeginV1 {
            dto_version: AGENT_INSTALLATION_DTO_VERSION,
            idempotency_key: operation_key.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            operation,
            scope: scope_for_workspace(workspace.as_ref(), shared),
            workspace_path: workspace_path(workspace),
            source_locator,
            replace_acknowledged,
            requested_slot,
            execution_kind: None,
            primary_slot_id: None,
            auto_select_first_exact: yes,
        }))
        .await
        .context("sending agent operation to daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected agent operation: {error}"))?;
    match response {
        Response::AgentInstallation(AgentInstallationResultV1::Receipt {
            status,
            installation_id,
            ..
        }) => println!(
            "agent operation completed: {status:?}{}",
            installation_id
                .map(|id| format!(" ({id})"))
                .unwrap_or_default()
        ),
        Response::AgentInstallation(AgentInstallationResultV1::NeedsChoice {
            continuation_token,
            choices,
            ..
        }) => {
            println!("agent binding needs a choice; continuation={continuation_token}");
            for choice in choices {
                println!(
                    "{}\t{}/{}",
                    choice.choice_id, choice.provider_id, choice.model_id
                );
            }
        }
        Response::AgentInstallation(AgentInstallationResultV1::Error { error }) => {
            bail!("agent operation refused: {:?}", error.code)
        }
        _ => bail!("daemon returned unexpected response to agent operation"),
    }
    Ok(())
}

async fn inspect(installation_id: String, workspace: Option<PathBuf>, shared: bool) -> Result<()> {
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for agent inspect")?;
    let response = daemon
        .client
        .request(Request::AgentInstallationInspect(AgentInstallationReadV1 {
            dto_version: AGENT_INSTALLATION_DTO_VERSION,
            scope: scope_for_workspace(workspace.as_ref(), shared),
            workspace_path: workspace_path(workspace),
            installation_id: Some(installation_id),
        }))
        .await
        .context("sending agent inspect to daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected agent inspect: {error}"))?;
    match response {
        Response::AgentInstallation(AgentInstallationResultV1::Inspected {
            installation: Some(record),
        }) => println!(
            "{}\t{}\t{}",
            record.installation_id,
            record.source_agent_id,
            record.source_revision.unwrap_or_default()
        ),
        Response::AgentInstallation(AgentInstallationResultV1::Inspected {
            installation: None,
        }) => bail!("agent installation was not found"),
        _ => bail!("daemon returned unexpected response to agent inspect"),
    }
    Ok(())
}

async fn create(
    path: Option<PathBuf>,
    description: Option<String>,
    execution_kind: String,
    primary_slot: String,
    workspace: Option<PathBuf>,
    shared: bool,
    operation_key: Option<String>,
) -> Result<()> {
    let path =
        path.ok_or_else(|| anyhow::anyhow!("--path is required for `cockpit agent create`"))?;
    let requested_path = path.to_string_lossy().into_owned();
    let _description = description;
    // `--path` is an opaque request value at the client boundary. The daemon
    // alone validates/derives its requested identity and chooses the owned
    // destination; this process never stats, opens, or writes it.
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for agent create")?;
    let response = daemon
        .client
        .request(Request::AgentInstallationBegin(AgentInstallationBeginV1 {
            dto_version: AGENT_INSTALLATION_DTO_VERSION,
            idempotency_key: operation_key.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            operation: AgentInstallationOperationKind::Create,
            scope: scope_for_workspace(workspace.as_ref(), shared),
            workspace_path: workspace_path(workspace),
            source_locator: requested_path,
            replace_acknowledged: false,
            requested_slot: None,
            execution_kind: Some(parse_execution_kind(&execution_kind)?),
            primary_slot_id: Some(primary_slot),
            auto_select_first_exact: false,
        }))
        .await
        .context("sending agent create to daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected agent create: {error}"))?;
    let Response::AgentInstallation(AgentInstallationResultV1::Receipt { status, .. }) = response
    else {
        bail!("daemon returned an unexpected response to agent create");
    };
    println!("agent creation completed: {status:?}");
    Ok(())
}

async fn list(workspace: Option<PathBuf>, shared: bool) -> Result<()> {
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for agent list")?;
    let response = daemon
        .client
        .request(Request::AgentInstallationList(AgentInstallationReadV1 {
            dto_version: AGENT_INSTALLATION_DTO_VERSION,
            scope: scope_for_workspace(workspace.as_ref(), shared),
            workspace_path: workspace_path(workspace),
            installation_id: None,
        }))
        .await
        .context("sending agent list to daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected agent list: {error}"))?;
    let Response::AgentInstallation(AgentInstallationResultV1::Listed { installations }) = response
    else {
        bail!("daemon returned an unexpected response to agent list");
    };
    for installation in installations {
        println!(
            "{}\t{}\t{}",
            installation.installation_id,
            installation.source_agent_id,
            installation.source_revision.unwrap_or_default()
        );
    }
    Ok(())
}

fn scope_for_workspace(workspace: Option<&PathBuf>, shared: bool) -> AgentInstallationScopeWire {
    match (workspace.is_some(), shared) {
        (false, false) => AgentInstallationScopeWire::Global,
        (true, false) => AgentInstallationScopeWire::WorkspacePrivate,
        (true, true) => AgentInstallationScopeWire::WorkspaceShared,
        // Clap rejects this shape, but preserve a fail-closed daemon request
        // if a programmatic caller ever constructs it.
        (false, true) => AgentInstallationScopeWire::WorkspaceShared,
    }
}

fn workspace_path(workspace: Option<PathBuf>) -> Option<String> {
    workspace.map(|path| path.to_string_lossy().into_owned())
}

fn parse_execution_kind(value: &str) -> Result<cockpit_proto::AgentInstallationExecutionKindV1> {
    match value {
        "assistant" => Ok(cockpit_proto::AgentInstallationExecutionKindV1::Assistant),
        "coding" => Ok(cockpit_proto::AgentInstallationExecutionKindV1::Coding),
        "computer" => Ok(cockpit_proto::AgentInstallationExecutionKindV1::Computer),
        _ => bail!("unsupported agent execution kind"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    use crate::cli::Cli;

    #[test]
    fn agent_installation_daemon_cli_create_uses_daemon_transport_not_direct_filesystem() {
        let source = include_str!("agent.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production agent command source");
        assert!(source.contains("ensure_persistent_daemon"));
        assert!(source.contains("Request::AgentInstallationBegin"));
        assert!(!source.contains("std::fs::write"));
        assert!(!source.contains("std::fs::create_dir_all"));
        assert!(!source.contains("path.is_dir()"));
        assert!(!source.contains("path.file_stem()"));
        assert!(!source.contains("path.extension()"));
    }

    #[test]
    fn agent_installation_daemon_cli_routes_all_mutations_over_rpc() {
        let source = include_str!("agent.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production agent command source");
        for command in [
            "AgentCommand::Install",
            "AgentCommand::Update",
            "AgentCommand::Bind",
            "AgentCommand::Inspect",
            "Request::AgentInstallationBegin",
            "Request::AgentInstallationInspect",
            "Request::AgentInstallationList",
        ] {
            assert!(
                source.contains(command),
                "missing daemon transport: {command}"
            );
        }
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

    #[test]
    fn agent_installation_cli_preserves_retry_key_and_noninteractive_choice_intent() {
        let cli = Cli::try_parse_from([
            "cockpit",
            "agent",
            "bind",
            "installation",
            "--operation-key",
            "retry-key",
            "--yes",
        ])
        .expect("parse bind");
        let Some(crate::cli::Command::Agent(AgentCommand::Bind {
            operation_key, yes, ..
        })) = cli.command
        else {
            panic!("expected agent bind")
        };
        assert_eq!(operation_key.as_deref(), Some("retry-key"));
        assert!(yes);

        let cli = Cli::try_parse_from([
            "cockpit",
            "agent",
            "submit-choice",
            "continuation",
            "--defer",
        ])
        .expect("parse defer");
        let Some(crate::cli::Command::Agent(AgentCommand::SubmitChoice {
            choice_id, defer, ..
        })) = cli.command
        else {
            panic!("expected agent defer")
        };
        assert!(defer);
        assert!(choice_id.is_none());
    }
}
