use std::fmt;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};

use crate::cli::{AgentCommand, AgentExecutionKindArg, AgentScopeArg};
use crate::daemon::client::ensure_persistent_daemon;
use crate::daemon::proto::{
    AGENT_INSTALLATION_DTO_VERSION, AgentInstallationBeginV1, AgentInstallationBindingOutcomeV1,
    AgentInstallationErrorCodeV1, AgentInstallationOperationKind, AgentInstallationReadV1,
    AgentInstallationReceiptStatusV1, AgentInstallationResultV1, AgentInstallationScopeWire,
    AgentInstallationSubmitChoiceV1, Request, Response,
};

/// A stable, machine-meaningful terminal outcome for `cockpit agent`.
///
/// Daemon errors remain redacted DTOs. This type only maps those fixed public
/// outcomes to process exit codes; it never adds client-derived state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCommandError {
    exit_code: u8,
    message: String,
}

impl AgentCommandError {
    const NEEDS_CHOICE: u8 = 3;
    const ACKNOWLEDGEMENT_REQUIRED: u8 = 4;
    const PRIMARY_UNUSABLE: u8 = 5;
    const OPTIONAL_UNBOUND: u8 = 6;
    const REBIND_REQUIRED: u8 = 7;
    const CONFLICT: u8 = 8;

    fn new(exit_code: u8, message: impl Into<String>) -> Self {
        Self {
            exit_code,
            message: message.into(),
        }
    }

    pub fn exit_code(&self) -> u8 {
        self.exit_code
    }
}

impl fmt::Display for AgentCommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AgentCommandError {}

pub async fn run(cmd: AgentCommand) -> Result<()> {
    match cmd {
        AgentCommand::Install {
            source,
            scope,
            workspace,
            operation_key,
            yes,
        } => {
            begin(BeginInput {
                source_locator: source,
                operation: AgentInstallationOperationKind::Install,
                scope,
                workspace,
                operation_key,
                yes,
                ..BeginInput::default()
            })
            .await
        }
        AgentCommand::Update {
            installation_id,
            source,
            replace,
            scope,
            workspace,
            operation_key,
            yes,
        } => {
            // Keep the documented installation-id grammar at the client
            // boundary. The daemon resolves provenance and replacement within
            // the requested scope; the CLI never reads the installed copy.
            uuid::Uuid::parse_str(&installation_id)
                .context("update INSTALLATION_ID must be a UUID")?;
            begin(BeginInput {
                source_locator: source,
                operation: AgentInstallationOperationKind::Update,
                replace_acknowledged: replace,
                scope,
                workspace,
                operation_key,
                yes,
                target_installation_id: Some(installation_id),
                ..BeginInput::default()
            })
            .await
        }
        AgentCommand::Bind {
            installation_id,
            slot,
            scope,
            workspace,
            operation_key,
            yes,
            provider_profile,
            model,
            defer,
        } => {
            begin(BeginInput {
                source_locator: installation_id,
                operation: AgentInstallationOperationKind::Bind,
                requested_slot: Some(slot),
                scope,
                workspace,
                operation_key,
                yes,
                defer,
                displayed_choice_selector: provider_profile.zip(model),
                ..BeginInput::default()
            })
            .await
        }
        AgentCommand::SubmitChoice {
            continuation_token,
            choice_id,
            defer,
        } => submit_choice(continuation_token, choice_id, defer).await,
        AgentCommand::Inspect {
            installation_id,
            scope,
            workspace,
            json,
        } => inspect(installation_id, scope, workspace, json).await,
        AgentCommand::Create {
            name,
            scope,
            execution_kind,
            primary_slot,
            workspace,
            operation_key,
        } => {
            create(
                name,
                scope,
                execution_kind,
                primary_slot,
                workspace,
                operation_key,
            )
            .await
        }
        AgentCommand::List {
            scope,
            workspace,
            json,
        } => list(scope, workspace, json).await,
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
    render_agent_response(response, false, true)
}

struct BeginInput {
    source_locator: String,
    operation: AgentInstallationOperationKind,
    replace_acknowledged: bool,
    requested_slot: Option<String>,
    scope: Option<AgentScopeArg>,
    workspace: Option<PathBuf>,
    operation_key: Option<String>,
    yes: bool,
    defer: bool,
    displayed_choice_selector: Option<(String, String)>,
    target_installation_id: Option<String>,
}

impl Default for BeginInput {
    fn default() -> Self {
        Self {
            source_locator: String::new(),
            operation: AgentInstallationOperationKind::Install,
            replace_acknowledged: false,
            requested_slot: None,
            scope: None,
            workspace: None,
            operation_key: None,
            yes: false,
            defer: false,
            displayed_choice_selector: None,
            target_installation_id: None,
        }
    }
}

async fn begin(input: BeginInput) -> Result<()> {
    let BeginInput {
        source_locator,
        operation,
        replace_acknowledged,
        requested_slot,
        scope,
        workspace,
        operation_key,
        yes,
        defer,
        displayed_choice_selector,
        target_installation_id,
    } = input;
    let (scope, workspace_path) = scope_request(
        scope,
        workspace,
        matches!(operation, AgentInstallationOperationKind::Install),
    )?;
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for agent operation")?;
    let response = daemon
        .client
        .request(Request::AgentInstallationBegin(AgentInstallationBeginV1 {
            dto_version: AGENT_INSTALLATION_DTO_VERSION,
            idempotency_key: operation_key.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            operation,
            scope,
            workspace_path,
            source_locator,
            target_installation_id,
            replace_acknowledged,
            requested_slot,
            execution_kind: None,
            primary_slot_id: None,
            auto_select_first_exact: yes,
        }))
        .await
        .context("sending agent operation to daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected agent operation: {error}"))?;
    if let Response::AgentInstallation(AgentInstallationResultV1::NeedsChoice {
        continuation_token,
        choices,
        unmatched_recommendations,
        ..
    }) = &response
    {
        render_choice_set(continuation_token, choices, unmatched_recommendations);
        if let Some((provider_profile, model)) = displayed_choice_selector {
            let choice = select_displayed_choice(choices, &provider_profile, &model)
                .map_err(anyhow::Error::new)?;
            // This is a display-only comparison. The mutation transmits only
            // the daemon-issued choice id, never a profile/route handle.
            return submit_choice(
                continuation_token.clone(),
                Some(choice.choice_id.clone()),
                false,
            )
            .await;
        }
        if defer {
            return submit_choice(continuation_token.clone(), None, true).await;
        }
        if stdin_is_interactive() && !yes {
            let choice_id = prompt_for_choice(choices)?;
            return submit_choice(
                continuation_token.clone(),
                choice_id.clone(),
                choice_id.is_none(),
            )
            .await;
        }
        return Err(anyhow!(AgentCommandError::new(
            AgentCommandError::NEEDS_CHOICE,
            "agent binding requires a daemon-issued choice"
        )));
    }
    render_agent_response(response, false, false)
}

async fn inspect(
    installation_id: String,
    scope: Option<AgentScopeArg>,
    workspace: Option<PathBuf>,
    json: bool,
) -> Result<()> {
    let (scope, workspace_path) = scope_request(scope, workspace, false)?;
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for agent inspect")?;
    let response = daemon
        .client
        .request(Request::AgentInstallationInspect(AgentInstallationReadV1 {
            dto_version: AGENT_INSTALLATION_DTO_VERSION,
            scope,
            workspace_path,
            installation_id: Some(installation_id),
        }))
        .await
        .context("sending agent inspect to daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected agent inspect: {error}"))?;
    if json {
        return print_json_response(&response);
    }
    match response {
        Response::AgentInstallation(AgentInstallationResultV1::Inspected {
            installation: Some(record),
        }) => print_record(&record),
        Response::AgentInstallation(AgentInstallationResultV1::Inspected {
            installation: None,
        }) => {
            return Err(anyhow!(AgentCommandError::new(
                AgentCommandError::CONFLICT,
                "agent installation was not found"
            )));
        }
        response => return render_agent_response(response, false, false),
    }
    Ok(())
}

async fn create(
    name: String,
    scope: Option<AgentScopeArg>,
    execution_kind: AgentExecutionKindArg,
    primary_slot: String,
    workspace: Option<PathBuf>,
    operation_key: Option<String>,
) -> Result<()> {
    ensure_agent_name(&name)?;
    let (scope, workspace_path) = scope_request(scope, workspace, true)?;
    // This is a declarative daemon identity, not a path the CLI inspects.
    // The daemon derives and validates the owned filename and destination.
    let requested_name = format!("authored/{name}");
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for agent create")?;
    let response = daemon
        .client
        .request(Request::AgentInstallationBegin(AgentInstallationBeginV1 {
            dto_version: AGENT_INSTALLATION_DTO_VERSION,
            idempotency_key: operation_key.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            operation: AgentInstallationOperationKind::Create,
            scope,
            workspace_path,
            source_locator: requested_name,
            target_installation_id: None,
            replace_acknowledged: false,
            requested_slot: None,
            execution_kind: Some(execution_kind.into()),
            primary_slot_id: Some(primary_slot),
            auto_select_first_exact: false,
        }))
        .await
        .context("sending agent create to daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected agent create: {error}"))?;
    render_agent_response(response, false, false)
}

async fn list(scope: Option<AgentScopeArg>, workspace: Option<PathBuf>, json: bool) -> Result<()> {
    let (scope, workspace_path) = scope_request(scope, workspace, false)?;
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for agent list")?;
    let response = daemon
        .client
        .request(Request::AgentInstallationList(AgentInstallationReadV1 {
            dto_version: AGENT_INSTALLATION_DTO_VERSION,
            scope,
            workspace_path,
            installation_id: None,
        }))
        .await
        .context("sending agent list to daemon")?
        .map_err(|error| anyhow::anyhow!("daemon rejected agent list: {error}"))?;
    if json {
        return print_json_response(&response);
    }
    match response {
        Response::AgentInstallation(AgentInstallationResultV1::Listed { installations }) => {
            for installation in installations {
                print_record(&installation);
            }
            Ok(())
        }
        response => render_agent_response(response, false, false),
    }
}

fn print_json_response(response: &Response) -> Result<()> {
    let Response::AgentInstallation(result) = response else {
        bail!("daemon returned unexpected response to agent command");
    };
    println!(
        "{}",
        serde_json::to_string(result).context("serializing agent daemon DTO")?
    );
    terminal_result(result)
}

fn render_agent_response(response: Response, json: bool, choice_submission: bool) -> Result<()> {
    if json {
        return print_json_response(&response);
    }
    let Response::AgentInstallation(result) = response else {
        bail!("daemon returned unexpected response to agent command");
    };
    match result {
        AgentInstallationResultV1::Receipt {
            operation_id,
            status,
            installation_id,
            source_revision,
            binding_outcome,
        } => {
            println!(
                "agent {}: status={}{}{}{}",
                if choice_submission {
                    "choice"
                } else {
                    "operation"
                },
                receipt_label(status),
                installation_id
                    .as_ref()
                    .map(|id| format!(" installation={id}"))
                    .unwrap_or_default(),
                source_revision
                    .as_ref()
                    .map(|revision| format!(" revision={revision}"))
                    .unwrap_or_default(),
                binding_outcome
                    .as_ref()
                    .map(|outcome| format!(" binding={}", binding_label(*outcome)))
                    .unwrap_or_default(),
            );
            terminal_result(&AgentInstallationResultV1::Receipt {
                operation_id,
                status,
                installation_id,
                source_revision,
                binding_outcome,
            })
        }
        AgentInstallationResultV1::NeedsChoice {
            continuation_token,
            choices,
            unmatched_recommendations,
            ..
        } => {
            render_choice_set(&continuation_token, &choices, &unmatched_recommendations);
            terminal_result(&AgentInstallationResultV1::NeedsChoice {
                continuation_token,
                choices,
                unmatched_recommendations,
                expires_at_unix_ms: 0,
            })
        }
        AgentInstallationResultV1::Listed { installations } => {
            for record in installations {
                print_record(&record);
            }
            Ok(())
        }
        AgentInstallationResultV1::Inspected {
            installation: Some(record),
        } => {
            print_record(&record);
            Ok(())
        }
        AgentInstallationResultV1::Inspected { installation: None } => {
            Err(anyhow!(AgentCommandError::new(
                AgentCommandError::CONFLICT,
                "agent installation was not found"
            )))
        }
        AgentInstallationResultV1::Error { error } => Err(anyhow!(AgentCommandError::new(
            error_exit_code(error.code),
            format!("agent operation refused: {}", error.message)
        ))),
    }
}

fn terminal_result(result: &AgentInstallationResultV1) -> Result<()> {
    match result {
        AgentInstallationResultV1::Receipt {
            status,
            binding_outcome,
            ..
        } => {
            let status = (*binding_outcome).map(binding_status).unwrap_or(*status);
            match status {
                AgentInstallationReceiptStatusV1::PrimaryUnusable => {
                    Err(anyhow!(AgentCommandError::new(
                        AgentCommandError::PRIMARY_UNUSABLE,
                        "agent primary slot remains unbound"
                    )))
                }
                AgentInstallationReceiptStatusV1::OptionalUnbound => {
                    Err(anyhow!(AgentCommandError::new(
                        AgentCommandError::OPTIONAL_UNBOUND,
                        "agent optional slot remains unbound"
                    )))
                }
                AgentInstallationReceiptStatusV1::Refused => Err(anyhow!(AgentCommandError::new(
                    AgentCommandError::CONFLICT,
                    "agent operation was refused"
                ))),
                _ => Ok(()),
            }
        }
        AgentInstallationResultV1::NeedsChoice { .. } => Err(anyhow!(AgentCommandError::new(
            AgentCommandError::NEEDS_CHOICE,
            "agent binding requires a daemon-issued choice"
        ))),
        AgentInstallationResultV1::Error { error } => Err(anyhow!(AgentCommandError::new(
            error_exit_code(error.code),
            format!("agent operation refused: {}", error.message)
        ))),
        AgentInstallationResultV1::Listed { .. } | AgentInstallationResultV1::Inspected { .. } => {
            Ok(())
        }
    }
}

fn binding_status(outcome: AgentInstallationBindingOutcomeV1) -> AgentInstallationReceiptStatusV1 {
    match outcome {
        AgentInstallationBindingOutcomeV1::Bound => AgentInstallationReceiptStatusV1::Bound,
        AgentInstallationBindingOutcomeV1::OptionalUnbound => {
            AgentInstallationReceiptStatusV1::OptionalUnbound
        }
        AgentInstallationBindingOutcomeV1::PrimaryUnusable => {
            AgentInstallationReceiptStatusV1::PrimaryUnusable
        }
    }
}

fn receipt_label(status: AgentInstallationReceiptStatusV1) -> &'static str {
    match status {
        AgentInstallationReceiptStatusV1::Installed => "installed",
        AgentInstallationReceiptStatusV1::Updated => "updated",
        AgentInstallationReceiptStatusV1::Bound => "bound",
        AgentInstallationReceiptStatusV1::Created => "created",
        AgentInstallationReceiptStatusV1::OptionalUnbound => "optional-unbound",
        AgentInstallationReceiptStatusV1::PrimaryUnusable => "primary-unusable",
        AgentInstallationReceiptStatusV1::TimedOut => "timed-out",
        AgentInstallationReceiptStatusV1::Refused => "refused",
    }
}

fn binding_label(outcome: AgentInstallationBindingOutcomeV1) -> &'static str {
    receipt_label(binding_status(outcome))
}

fn error_exit_code(code: AgentInstallationErrorCodeV1) -> u8 {
    match code {
        AgentInstallationErrorCodeV1::UnknownChoice
        | AgentInstallationErrorCodeV1::ContinuationExpired => AgentCommandError::NEEDS_CHOICE,
        AgentInstallationErrorCodeV1::Collision => AgentCommandError::ACKNOWLEDGEMENT_REQUIRED,
        AgentInstallationErrorCodeV1::StaleBinding => AgentCommandError::REBIND_REQUIRED,
        AgentInstallationErrorCodeV1::DirtySharedFile
        | AgentInstallationErrorCodeV1::IdempotencyConflict => AgentCommandError::CONFLICT,
        AgentInstallationErrorCodeV1::IncompatibleModel => AgentCommandError::PRIMARY_UNUSABLE,
        _ => 1,
    }
}

fn render_choice_set(
    continuation_token: &str,
    choices: &[crate::daemon::proto::AgentInstallationChoiceV1],
    unmatched: &[crate::daemon::proto::AgentInstallationUnmatchedRecommendationV1],
) {
    for line in choice_set_lines(continuation_token, choices, unmatched) {
        println!("{line}");
    }
}

fn choice_set_lines(
    continuation_token: &str,
    choices: &[crate::daemon::proto::AgentInstallationChoiceV1],
    unmatched: &[crate::daemon::proto::AgentInstallationUnmatchedRecommendationV1],
) -> Vec<String> {
    let mut lines = vec![format!(
        "agent binding needs a choice; continuation={continuation_token}"
    )];
    for choice in choices {
        let recommendation = choice.recommendation_id.as_deref().unwrap_or("unsuggested");
        let upstream = choice
            .canonical_upstream_identity
            .as_deref()
            .unwrap_or("local route");
        lines.push(format!(
            "choice={} slot={} provider={} model={} recommendation={} upstream={}{}{}",
            choice.choice_id,
            choice.slot_id,
            choice.provider_id,
            choice.model_id,
            recommendation,
            upstream,
            choice
                .author_label
                .as_deref()
                .map(|value| format!(" label={value}"))
                .unwrap_or_default(),
            choice
                .rationale
                .as_deref()
                .map(|value| format!(" rationale={value}"))
                .unwrap_or_default()
        ));
    }
    for recommendation in unmatched {
        lines.push(format!(
            "unmatched-recommendation={} upstream={}{}{}",
            recommendation.recommendation_id,
            recommendation.canonical_upstream_identity,
            recommendation
                .author_label
                .as_deref()
                .map(|value| format!(" label={value}"))
                .unwrap_or_default(),
            recommendation
                .rationale
                .as_deref()
                .map(|value| format!(" rationale={value}"))
                .unwrap_or_default()
        ));
    }
    lines
}

fn select_displayed_choice<'a>(
    choices: &'a [crate::daemon::proto::AgentInstallationChoiceV1],
    provider_profile: &str,
    model: &str,
) -> std::result::Result<&'a crate::daemon::proto::AgentInstallationChoiceV1, AgentCommandError> {
    let mut matches = choices
        .iter()
        .filter(|choice| choice.provider_id == provider_profile && choice.model_id == model);
    let choice = matches.next().ok_or_else(|| {
        AgentCommandError::new(
            AgentCommandError::PRIMARY_UNUSABLE,
            "the selected displayed provider/model is not a daemon-confirmed compatible choice",
        )
    })?;
    if matches.next().is_some() {
        return Err(AgentCommandError::new(
            AgentCommandError::CONFLICT,
            "the selected displayed provider/model is ambiguous; submit a daemon-issued choice id",
        ));
    }
    Ok(choice)
}

fn print_record(record: &crate::daemon::proto::AgentInstallationRecordV1) {
    println!("{}", record_line(record));
}

fn record_line(record: &crate::daemon::proto::AgentInstallationRecordV1) -> String {
    let bindings = if record.bindings.is_empty() {
        "unbound".to_owned()
    } else {
        let mut sorted = record.bindings.clone();
        sorted.sort_by(|a, b| slot_order(&a.slot_id).cmp(&slot_order(&b.slot_id)));
        sorted
            .iter()
            .map(|binding| {
                format!(
                    "{}={:?}({})",
                    binding.slot_id, binding.state, binding.model_id
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    };
    let binding = if record.scope == AgentInstallationScopeWire::WorkspaceShared {
        String::new()
    } else {
        format!(" binding={bindings}")
    };
    format!(
        "scope={} installation={} agent={} source={} version={} digest={} revision={}{}",
        scope_label(record.scope),
        record.installation_id,
        record.source_agent_id,
        record.source_identity,
        record.source_revision.as_deref().unwrap_or("unknown"),
        record.source_digest,
        record.installation_revision,
        binding,
    )
}

/// Sort key for model-slot bindings so `primary` always appears first in
/// rendered output, followed by other slots in alphabetical order.
fn slot_order(slot_id: &str) -> (u8, &str) {
    if slot_id == "primary" {
        (0, slot_id)
    } else {
        (1, slot_id)
    }
}

fn scope_request(
    scope: Option<AgentScopeArg>,
    workspace: Option<PathBuf>,
    require_explicit: bool,
) -> Result<(AgentInstallationScopeWire, Option<String>)> {
    let scope = match scope {
        Some(scope) => scope,
        None if require_explicit && stdin_is_interactive() => prompt_for_scope()?,
        None if require_explicit => {
            return Err(anyhow!(crate::commands::CommandUsageError::new(
                "--scope is required outside an interactive terminal"
            )));
        }
        None => AgentScopeArg::Global,
    };
    let scope = match scope {
        AgentScopeArg::Global => AgentInstallationScopeWire::Global,
        AgentScopeArg::WorkspacePrivate => AgentInstallationScopeWire::WorkspacePrivate,
        AgentScopeArg::Workspace => AgentInstallationScopeWire::WorkspaceShared,
    };
    match (scope, workspace) {
        (AgentInstallationScopeWire::Global, None) => Ok((scope, None)),
        (AgentInstallationScopeWire::Global, Some(_)) => {
            Err(anyhow!(crate::commands::CommandUsageError::new(
                "--workspace is only valid with a workspace scope"
            )))
        }
        (_, Some(path)) => Ok((scope, Some(path.to_string_lossy().into_owned()))),
        (_, None) => Err(anyhow!(crate::commands::CommandUsageError::new(
            "--workspace is required with workspace-private or workspace scope"
        ))),
    }
}

fn stdin_is_interactive() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

fn prompt_for_scope() -> Result<AgentScopeArg> {
    print!("Agent scope [global, workspace-private, workspace]: ");
    io::stdout()
        .flush()
        .context("flushing agent scope prompt")?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("reading agent scope")?;
    match input.trim() {
        "global" => Ok(AgentScopeArg::Global),
        "workspace-private" => Ok(AgentScopeArg::WorkspacePrivate),
        "workspace" => Ok(AgentScopeArg::Workspace),
        _ => Err(anyhow!(crate::commands::CommandUsageError::new(
            "scope must be global, workspace-private, or workspace"
        ))),
    }
}

fn prompt_for_choice(
    choices: &[crate::daemon::proto::AgentInstallationChoiceV1],
) -> Result<Option<String>> {
    print!("Choice id (or `defer`): ");
    io::stdout()
        .flush()
        .context("flushing agent choice prompt")?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("reading agent choice")?;
    let choice = input.trim();
    if choice == "defer" {
        return Ok(None);
    }
    if choices
        .iter()
        .any(|candidate| candidate.choice_id == choice)
    {
        return Ok(Some(choice.to_owned()));
    }
    Err(anyhow!(crate::commands::CommandUsageError::new(
        "choice must be one issued by the daemon or `defer`"
    )))
}

fn ensure_agent_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(anyhow!(crate::commands::CommandUsageError::new(
            "NAME must contain only ASCII letters, digits, `-`, or `_`"
        )));
    }
    Ok(())
}

fn scope_label(scope: AgentInstallationScopeWire) -> &'static str {
    match scope {
        AgentInstallationScopeWire::Global => "Global",
        AgentInstallationScopeWire::WorkspacePrivate => "Workspace private",
        AgentInstallationScopeWire::WorkspaceShared => "Workspace",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    use crate::cli::Cli;

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

    #[test]
    fn agent_cli_management_scope_values_are_explicit_and_workspace_scoped() {
        assert_eq!(
            scope_request(Some(AgentScopeArg::Global), None, true)
                .unwrap()
                .0,
            AgentInstallationScopeWire::Global
        );
        assert_eq!(
            scope_request(
                Some(AgentScopeArg::WorkspacePrivate),
                Some(PathBuf::from("workspace")),
                true,
            )
            .unwrap()
            .0,
            AgentInstallationScopeWire::WorkspacePrivate
        );
        assert_eq!(
            scope_request(
                Some(AgentScopeArg::Workspace),
                Some(PathBuf::from("workspace")),
                true,
            )
            .unwrap()
            .0,
            AgentInstallationScopeWire::WorkspaceShared
        );
        assert!(scope_request(Some(AgentScopeArg::Workspace), None, true).is_err());
        assert!(
            scope_request(
                Some(AgentScopeArg::Global),
                Some(PathBuf::from("workspace")),
                true
            )
            .is_err()
        );
    }

    #[test]
    fn agent_cli_management_parser_covers_install_update_create_and_bind_grammar() {
        let install = Cli::try_parse_from([
            "cockpit",
            "agent",
            "install",
            "owner/repo@main:agents/helper.md",
            "--scope",
            "global",
        ])
        .expect("parse install");
        assert!(matches!(
            install.command,
            Some(crate::cli::Command::Agent(AgentCommand::Install {
                scope: Some(AgentScopeArg::Global),
                ..
            }))
        ));
        let malformed = Cli::try_parse_from([
            "cockpit",
            "agent",
            "install",
            "not-a-github-locator",
            "--scope",
            "global",
        ])
        .expect("CLI forwards source validation to the daemon");
        assert!(matches!(
            malformed.command,
            Some(crate::cli::Command::Agent(AgentCommand::Install { source, .. }))
                if source == "not-a-github-locator"
        ));
        Cli::try_parse_from([
            "cockpit",
            "agent",
            "update",
            "00000000-0000-0000-0000-000000000001",
            "--source",
            "owner/repo@deadbeef:agents/helper.md",
            "--replace",
        ])
        .expect("parse update replacement");
        Cli::try_parse_from([
            "cockpit",
            "agent",
            "create",
            "helper",
            "--scope",
            "workspace",
            "--workspace",
            "workspace",
            "--execution-kind",
            "coding",
        ])
        .expect("parse create");
        Cli::try_parse_from([
            "cockpit",
            "agent",
            "bind",
            "00000000-0000-0000-0000-000000000001",
            "--defer",
        ])
        .expect("parse bind defer");
        let provider_selector = Cli::try_parse_from([
            "cockpit",
            "agent",
            "bind",
            "00000000-0000-0000-0000-000000000001",
            "--provider-profile",
            "opaque-daemon-handle",
            "--model",
            "model",
        ])
        .expect("parse displayed daemon selector");
        assert!(matches!(
            provider_selector.command,
            Some(crate::cli::Command::Agent(AgentCommand::Bind {
                provider_profile: Some(provider_profile),
                model: Some(model),
                ..
            })) if provider_profile == "opaque-daemon-handle" && model == "model"
        ));
        let partial_selector = Cli::try_parse_from([
            "cockpit",
            "agent",
            "bind",
            "00000000-0000-0000-0000-000000000001",
            "--provider-profile",
            "displayed-provider",
        ])
        .unwrap_err();
        assert_eq!(
            partial_selector.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn agent_cli_management_create_identity_is_declarative_not_a_client_path() {
        ensure_agent_name("helper_1").expect("portable name");
        assert!(ensure_agent_name("../helper").is_err());
        assert!(ensure_agent_name("helper.md").is_err());
    }

    #[test]
    fn agent_cli_management_terminal_outcomes_have_distinct_exit_codes() {
        let needs_choice = AgentInstallationResultV1::NeedsChoice {
            continuation_token: "continuation".into(),
            choices: vec![],
            unmatched_recommendations: vec![],
            expires_at_unix_ms: 1,
        };
        let error = terminal_result(&needs_choice).unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<AgentCommandError>()
                .unwrap()
                .exit_code(),
            AgentCommandError::NEEDS_CHOICE
        );
        assert_ne!(
            error_exit_code(AgentInstallationErrorCodeV1::StaleBinding),
            error_exit_code(AgentInstallationErrorCodeV1::Collision)
        );
        assert_ne!(
            AgentCommandError::PRIMARY_UNUSABLE,
            AgentCommandError::OPTIONAL_UNBOUND
        );
        for (outcome, expected_exit) in [
            (
                AgentInstallationBindingOutcomeV1::PrimaryUnusable,
                AgentCommandError::PRIMARY_UNUSABLE,
            ),
            (
                AgentInstallationBindingOutcomeV1::OptionalUnbound,
                AgentCommandError::OPTIONAL_UNBOUND,
            ),
        ] {
            let error = terminal_result(&AgentInstallationResultV1::Receipt {
                operation_id: "operation".into(),
                status: AgentInstallationReceiptStatusV1::Bound,
                installation_id: Some("installation".into()),
                source_revision: None,
                binding_outcome: Some(outcome),
            })
            .unwrap_err();
            assert_eq!(
                error
                    .downcast_ref::<AgentCommandError>()
                    .expect("typed terminal failure")
                    .exit_code(),
                expected_exit
            );
        }
    }

    #[test]
    fn agent_cli_management_provider_selector_submits_only_an_exact_daemon_choice() {
        let choice = |choice_id: &str, provider_id: &str, model_id: &str| {
            crate::daemon::proto::AgentInstallationChoiceV1 {
                choice_id: choice_id.into(),
                slot_id: "primary".into(),
                offering_id: format!("offering-{choice_id}"),
                provider_id: provider_id.into(),
                model_id: model_id.into(),
                recommendation_id: None,
                canonical_upstream_identity: None,
                author_label: None,
                rationale: None,
                author_suggested: false,
                exact_alias_match: false,
            }
        };
        let choices = vec![
            choice("choice-a", "displayed-provider", "model-a"),
            choice("choice-b", "displayed-provider", "model-b"),
        ];
        assert_eq!(
            select_displayed_choice(&choices, "displayed-provider", "model-b")
                .unwrap()
                .choice_id,
            "choice-b"
        );
        assert_eq!(
            select_displayed_choice(&choices, "missing", "model-b")
                .unwrap_err()
                .exit_code(),
            AgentCommandError::PRIMARY_UNUSABLE
        );
        let secretish_selector = "opaque-daemon-profile-handle";
        let refusal = select_displayed_choice(&choices, secretish_selector, "model-b")
            .unwrap_err()
            .to_string();
        assert!(!refusal.contains(secretish_selector));
        let ambiguous = vec![
            choice("choice-a", "displayed-provider", "model-a"),
            choice("choice-b", "displayed-provider", "model-a"),
        ];
        assert_eq!(
            select_displayed_choice(&ambiguous, "displayed-provider", "model-a")
                .unwrap_err()
                .exit_code(),
            AgentCommandError::CONFLICT
        );
    }

    #[test]
    fn agent_cli_management_renders_daemon_choice_order_and_unmatched_upstream_identity() {
        let choice = |choice_id: &str,
                      provider_id: &str,
                      model_id: &str,
                      recommendation_id: Option<&str>,
                      upstream: Option<&str>| {
            crate::daemon::proto::AgentInstallationChoiceV1 {
                choice_id: choice_id.into(),
                slot_id: "primary".into(),
                offering_id: format!("offering-{choice_id}"),
                provider_id: provider_id.into(),
                model_id: model_id.into(),
                recommendation_id: recommendation_id.map(str::to_owned),
                canonical_upstream_identity: upstream.map(str::to_owned),
                author_label: Some(format!("label-{choice_id}")),
                rationale: Some(format!("why-{choice_id}")),
                author_suggested: recommendation_id.is_some(),
                exact_alias_match: recommendation_id.is_some(),
            }
        };
        let choices = vec![
            choice(
                "choice-0-offering-0",
                "vendor",
                "exact-a",
                Some("first"),
                Some("upstream/first"),
            ),
            choice(
                "choice-1-offering-1",
                "vendor",
                "exact-b",
                Some("second"),
                Some("upstream/second"),
            ),
            choice("choice-local-offering-2", "local", "compatible", None, None),
        ];
        let unmatched = vec![
            crate::daemon::proto::AgentInstallationUnmatchedRecommendationV1 {
                recommendation_id: "not-configured".into(),
                canonical_upstream_identity: "upstream/not-configured".into(),
                author_label: Some("Author's unavailable choice".into()),
                rationale: Some("not installed locally".into()),
            },
        ];

        let lines = choice_set_lines("continuation", &choices, &unmatched);
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.starts_with("choice="))
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec![
                "choice=choice-0-offering-0 slot=primary provider=vendor model=exact-a recommendation=first upstream=upstream/first label=label-choice-0-offering-0 rationale=why-choice-0-offering-0",
                "choice=choice-1-offering-1 slot=primary provider=vendor model=exact-b recommendation=second upstream=upstream/second label=label-choice-1-offering-1 rationale=why-choice-1-offering-1",
                "choice=choice-local-offering-2 slot=primary provider=local model=compatible recommendation=unsuggested upstream=local route label=label-choice-local-offering-2 rationale=why-choice-local-offering-2",
            ]
        );
        assert!(lines.iter().any(|line| line == "unmatched-recommendation=not-configured upstream=upstream/not-configured label=Author's unavailable choice rationale=not installed locally"));
        assert_eq!(
            select_displayed_choice(&choices, "local", "compatible")
                .expect("compatible unsuggested choice needs no acknowledgement")
                .choice_id,
            "choice-local-offering-2"
        );
    }

    #[test]
    fn agent_cli_management_text_labels_do_not_use_color_to_distinguish_scopes() {
        assert_eq!(scope_label(AgentInstallationScopeWire::Global), "Global");
        assert_eq!(
            scope_label(AgentInstallationScopeWire::WorkspacePrivate),
            "Workspace private"
        );
        assert_eq!(
            scope_label(AgentInstallationScopeWire::WorkspaceShared),
            "Workspace"
        );
    }

    #[test]
    fn agent_cli_management_shared_record_text_omits_local_binding_status() {
        let record = crate::daemon::proto::AgentInstallationRecordV1 {
            installation_id: "installation".into(),
            scope: AgentInstallationScopeWire::WorkspaceShared,
            source_agent_id: "authored/helper".into(),
            source_identity: "owner/repo:agents/helper.md".into(),
            source_revision: Some("a".repeat(40)),
            source_digest: "b".repeat(64),
            installation_revision: 1,
            bindings: vec![],
        };
        let text = record_line(&record);
        assert!(text.contains("scope=Workspace"));
        assert!(text.contains("source=owner/repo:agents/helper.md"));
        assert!(!text.contains("binding="));
        assert!(!text.contains("unbound"));
    }
}
