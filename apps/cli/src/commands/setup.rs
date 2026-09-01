use std::future::Future;
use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::pin::Pin;
#[cfg(test)]
use std::time::Duration;

use crate::cli::SetupArgs;
#[cfg(test)]
use crate::config::dirs::most_specific_config_write_target;
use crate::config::dirs::{global_config_dir, global_config_file};
#[cfg(test)]
use crate::config::providers::ConfigDoc;
use crate::config::providers::HeaderSpec;
use crate::daemon::client::ensure_persistent_daemon;
use crate::daemon::proto::{Request, Response, SecretInventoryEntry, SecretInventoryKind};
#[cfg(test)]
use crate::wizard::descriptor_for_cwd;
use crate::wizard::{
    StepKind, WizardAnswer, WizardDescriptor, WizardRun, compose_wizard_host_capabilities,
    descriptor_for_cwd_with_caps, provider_entry_from_answers, provider_id_answer,
    selected_provider_template,
};
use anyhow::{Context, Result, anyhow, bail};

pub async fn run(args: SetupArgs) -> Result<()> {
    let stdin_tty = io::stdin().is_terminal();
    let cwd = std::env::current_dir().context("getting cwd")?;
    let mut io = StdTerminalIo;
    let host_capabilities = compose_wizard_host_capabilities(&cwd).await;
    let wizard_cwd = global_config_dir().context("resolving global config for setup")?;
    let wizard = match args.wizard.as_deref() {
        Some(id) => descriptor_for_cwd_with_caps(
            id,
            if matches!(
                id,
                cockpit_core::wizard::SECURITY_WIZARD_ID | cockpit_core::wizard::MODEL_WIZARD_ID
            ) {
                &wizard_cwd
            } else {
                &cwd
            },
            Some(&host_capabilities),
        )
        .ok_or_else(|| anyhow!("unknown setup wizard `{id}`; run `cockpit setup` to list"))?,
        None => choose_wizard(&mut io, stdin_tty, &cwd, &host_capabilities).await?,
    };
    let mut actions = ProviderSetupActions::new(cwd).with_host_capabilities(host_capabilities);
    run_terminal_wizard(wizard, &mut io, &stdin_tty, &mut actions).await?;
    Ok(())
}

pub async fn run_provider_add(template: Option<String>) -> Result<()> {
    let stdin_tty = io::stdin().is_terminal();
    let cwd = std::env::current_dir().context("getting cwd")?;
    if let Some(template) = template.as_deref()
        && crate::providers::template_by_id(template).is_none()
    {
        bail!("unknown provider template `{template}`; run `cockpit provider list`");
    }
    let wizard = crate::wizard::provider_descriptor_with_template(template.as_deref());
    let mut io = StdTerminalIo;
    let mut actions = ProviderSetupActions::new(cwd);
    run_terminal_wizard(wizard, &mut io, &stdin_tty, &mut actions).await?;
    Ok(())
}

async fn choose_wizard(
    io: &mut dyn TerminalIo,
    tty: bool,
    cwd: &std::path::Path,
    caps: &cockpit_proto::HostCapabilitySnapshot,
) -> Result<WizardDescriptor> {
    if !tty {
        bail!("cockpit setup requires an interactive stdin; run `cockpit` and use /setup instead");
    }
    io.write_line("Available setup wizards:")?;
    for (index, wizard) in crate::wizard::registry().iter().enumerate() {
        io.write_line(&format!(
            "  {}. {} - {}",
            index + 1,
            wizard.id,
            wizard.description
        ))?;
    }
    loop {
        io.write("Choose a wizard: ")?;
        let input = io.read_line()?.trim().to_string();
        if let Some(wizard) = resolve_wizard_choice(&input, cwd, Some(caps)) {
            return Ok(wizard);
        }
        io.write_line("Choose one of the listed wizard numbers or ids.")?;
    }
}

fn resolve_wizard_choice(
    input: &str,
    cwd: &std::path::Path,
    caps: Option<&cockpit_proto::HostCapabilitySnapshot>,
) -> Option<WizardDescriptor> {
    let id = if let Ok(number) = input.parse::<usize>() {
        crate::wizard::registry().get(number.checked_sub(1)?)?.id
    } else {
        input
    };
    let config_root = global_config_dir().ok()?;
    let descriptor_root = matches!(
        id,
        cockpit_core::wizard::SECURITY_WIZARD_ID | cockpit_core::wizard::MODEL_WIZARD_ID
    )
    .then_some(config_root.as_path())
    .unwrap_or(cwd);
    descriptor_for_cwd_with_caps(id, descriptor_root, caps)
}

pub(crate) trait TerminalIo {
    fn read_line(&mut self) -> io::Result<String>;
    fn write(&mut self, text: &str) -> io::Result<()>;

    fn write_line(&mut self, line: &str) -> io::Result<()> {
        self.write(line)?;
        self.write("\n")
    }
}

struct StdTerminalIo;

impl TerminalIo for StdTerminalIo {
    fn read_line(&mut self) -> io::Result<String> {
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        Ok(line)
    }

    fn write(&mut self, text: &str) -> io::Result<()> {
        use std::io::Write;

        let mut stdout = io::stdout();
        stdout.write_all(text.as_bytes())?;
        stdout.flush()
    }
}

pub(crate) trait TtyProbe {
    fn is_tty(&self) -> bool;
}

impl TtyProbe for bool {
    fn is_tty(&self) -> bool {
        *self
    }
}

pub(crate) type ActionFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + 'a>>;

pub(crate) trait TerminalActionHandler {
    fn run_action<'a>(
        &'a mut self,
        step_id: &'static str,
        run: &'a WizardRun,
        io: &'a mut dyn TerminalIo,
    ) -> ActionFuture<'a>;
}

pub(crate) async fn run_terminal_wizard(
    descriptor: WizardDescriptor,
    io: &mut dyn TerminalIo,
    tty: &dyn TtyProbe,
    actions: &mut dyn TerminalActionHandler,
) -> Result<WizardRun> {
    if !tty.is_tty() {
        bail!("cockpit setup requires an interactive stdin; run `cockpit` and use /setup instead");
    }

    let mut run = WizardRun::new(descriptor)?;
    while let Some(step) = run.current_step().cloned() {
        match &step.kind {
            StepKind::Select { .. } => {
                let options = run.select_options();
                write_select(io, &run, step.prompt, &options)?;
                let answer = loop {
                    let input = read_input(io)?;
                    if go_back(&mut run, &input, io)? {
                        break None;
                    }
                    if input.trim().is_empty()
                        && let Some(WizardAnswer::Select(value)) = run.prefill()
                    {
                        break Some(WizardAnswer::Select(value));
                    }
                    if let Some(answer) = select_answer(&options, input.trim()) {
                        break Some(answer);
                    }
                    io.write_line("Choose one of the listed numbers or ids.")?;
                };
                if let Some(answer) = answer {
                    submit(&mut run, answer, io)?;
                }
            }
            StepKind::Text | StepKind::Secret => {
                let default = match run.prefill() {
                    Some(WizardAnswer::Text(value) | WizardAnswer::Secret(value)) => Some(value),
                    _ => None,
                };
                io.write(step.prompt)?;
                if let Some(default) = &default
                    && !default.is_empty()
                {
                    io.write(&format!(" [{default}]"))?;
                }
                io.write(": ")?;
                let input = read_input(io)?;
                if go_back(&mut run, &input, io)? {
                    continue;
                }
                let value = if input.trim().is_empty() {
                    default.unwrap_or_default()
                } else {
                    input.trim_end().to_string()
                };
                let answer = if matches!(step.kind, StepKind::Secret) {
                    WizardAnswer::Secret(value)
                } else {
                    WizardAnswer::Text(value)
                };
                submit(&mut run, answer, io)?;
            }
            StepKind::Action { progress } => {
                io.write_line(progress)?;
                actions.run_action(step.id, &run, io).await?;
                submit(&mut run, WizardAnswer::Acknowledged, io)?;
            }
            StepKind::Info => {
                io.write_line(step.prompt)?;
                submit(&mut run, WizardAnswer::Acknowledged, io)?;
            }
            StepKind::Confirm => {
                let default = match run.prefill() {
                    Some(WizardAnswer::Confirm(value)) => Some(value),
                    _ => None,
                };
                let suffix = match default {
                    Some(true) => " [Y/n]: ",
                    Some(false) | None => " [y/N]: ",
                };
                io.write(&format!("{}{}", step.prompt, suffix))?;
                let input = read_input(io)?;
                if go_back(&mut run, &input, io)? {
                    continue;
                }
                let confirmed = if input.trim().is_empty() {
                    default.unwrap_or(false)
                } else {
                    matches!(input.trim(), "y" | "Y" | "yes" | "YES")
                };
                submit(&mut run, WizardAnswer::Confirm(confirmed), io)?;
            }
            StepKind::MultiToggle { options } => {
                io.write_line(step.prompt)?;
                let default = match run.prefill() {
                    Some(WizardAnswer::MultiToggle(values)) => values,
                    _ => Vec::new(),
                };
                for option in options {
                    let check = if default.iter().any(|value| value == option.id.as_ref()) {
                        "[x]"
                    } else {
                        "[ ]"
                    };
                    io.write_line(&format!("  {check} {} ({})", option.label, option.id))?;
                }
                io.write("Comma-separated ids (blank keeps current, none clears): ")?;
                let input = read_input(io)?;
                if go_back(&mut run, &input, io)? {
                    continue;
                }
                let values = if input.trim().is_empty() {
                    default
                } else if matches!(input.trim(), "none" | "None" | "NONE") {
                    Vec::new()
                } else {
                    input
                        .split(',')
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_string)
                        .collect()
                };
                submit(&mut run, WizardAnswer::MultiToggle(values), io)?;
            }
            StepKind::ToolSurface => {
                io.write_line(step.prompt)?;
                io.write_line("Available tools:")?;
                for item in crate::agents::tool_surface_catalog() {
                    let tiers = item
                        .tiers
                        .iter()
                        .map(|tier| tier.label())
                        .collect::<Vec<_>>()
                        .join("/");
                    io.write_line(&format!("  {} ({}, {})", item.name, item.family, tiers))?;
                }
                io.write("Comma-separated tool[:tier] entries (blank for none): ")?;
                let input = read_input(io)?;
                if go_back(&mut run, &input, io)? {
                    continue;
                }
                let answer = parse_tool_surface_answer(&input)?;
                submit(&mut run, WizardAnswer::ToolSurface(answer), io)?;
            }
        }
    }
    Ok(run)
}

fn parse_tool_surface_answer(input: &str) -> Result<crate::agents::ToolSurfaceSelection> {
    let known: std::collections::BTreeSet<&str> =
        crate::agents::known_tool_names().iter().copied().collect();
    let mut tools = Vec::new();
    let mut tool_tiers = std::collections::BTreeMap::new();
    for raw in input
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let (tool, tier) = raw
            .split_once(':')
            .map(|(tool, tier)| (tool.trim(), Some(tier.trim())))
            .unwrap_or((raw, None));
        if !known.contains(tool) {
            bail!("unknown tool `{tool}`");
        }
        if !tools.iter().any(|existing| existing == tool) {
            tools.push(tool.to_string());
        }
        if let Some(tier) = tier {
            let parsed = crate::agents::ToolTier::from_label(tier)
                .ok_or_else(|| anyhow::anyhow!("unknown tool tier `{tier}`"))?;
            if !crate::agents::legal_tool_tiers(tool).contains(&parsed) {
                bail!("tool `{tool}` cannot use tier `{tier}`");
            }
            tool_tiers.insert(tool.to_string(), parsed);
        }
    }
    Ok(crate::agents::ToolSurfaceSelection { tools, tool_tiers })
}

fn write_select(
    io: &mut dyn TerminalIo,
    run: &WizardRun,
    prompt: &str,
    options: &[crate::wizard::SelectOption],
) -> io::Result<()> {
    io.write_line(prompt)?;
    let help = run.help();
    if !help.is_empty() {
        io.write_line(help.as_ref())?;
    }
    if let Some(WizardAnswer::Select(current)) = run.answer(run.current_step_id().unwrap_or("")) {
        io.write_line(&format!("Current: {current}"))?;
    }
    for (index, option) in options.iter().enumerate() {
        io.write_line(&format!(
            "  {}. {} ({}) - {}",
            index + 1,
            option.label,
            option.id,
            option.description
        ))?;
    }
    io.write("Choice: ")
}

fn select_answer(options: &[crate::wizard::SelectOption], input: &str) -> Option<WizardAnswer> {
    if let Ok(number) = input.parse::<usize>() {
        return options
            .get(number.checked_sub(1)?)
            .map(|option| WizardAnswer::Select(option.id.to_string()));
    }
    options
        .iter()
        .find(|option| option.id == input)
        .map(|option| WizardAnswer::Select(option.id.to_string()))
}

fn read_input(io: &mut dyn TerminalIo) -> Result<String> {
    io.read_line().context("reading setup input")
}

fn go_back(run: &mut WizardRun, input: &str, io: &mut dyn TerminalIo) -> Result<bool> {
    if !matches!(input.trim(), "b" | "back") {
        return Ok(false);
    }
    if !run.back() {
        io.write_line("Already at the first step.")?;
    }
    Ok(true)
}

fn submit(run: &mut WizardRun, answer: WizardAnswer, io: &mut dyn TerminalIo) -> Result<()> {
    match run.submit(answer) {
        Ok(()) => Ok(()),
        Err(error) => {
            io.write_line(&error)?;
            Ok(())
        }
    }
}

async fn request_durable_local_mutation(
    client: &cockpit_client::DaemonClient,
    client_operation_id: &str,
    operation_kind: &str,
    request: Request,
) -> Result<Response> {
    let mut initial_rejection = match client.request(request.clone()).await {
        Ok(Ok(response)) => return Ok(response),
        Ok(Err(error)) => Some(error.to_string()),
        Err(_) => None,
    };
    let mut attempts = 0_u32;
    loop {
        let settlement = client
            .request(Request::GetLocalOperationSettlement {
                client_operation_id: client_operation_id.to_string(),
            })
            .await;
        match settlement {
            Ok(Ok(Response::LocalOperationSettlement {
                client_operation_id: returned_operation_id,
                operation_kind: returned_kind,
                pending,
                response,
                terminal_error,
                terminal_cancelled,
                ..
            })) if returned_operation_id == client_operation_id
                && returned_kind == operation_kind =>
            {
                if let Some(error) = terminal_error {
                    bail!("daemon rejected {operation_kind}: {error}");
                }
                if terminal_cancelled {
                    bail!("daemon cancelled {operation_kind}");
                }
                if let Some(response) = response {
                    return Ok(*response);
                }
                if !pending {
                    bail!("daemon returned an incomplete terminal settlement for {operation_kind}");
                }
            }
            Ok(Ok(other)) => {
                bail!("daemon returned an unbound settlement for {operation_kind}: {other:?}")
            }
            Ok(Err(error)) => {
                if let Some(rejection) = initial_rejection.as_deref() {
                    bail!("daemon rejected {operation_kind}: {rejection}");
                }
                // A response can be lost after the daemon accepted the
                // mutation but before its receipt became queryable. Re-submit
                // the exact same operation id/body periodically; daemon-side
                // fencing makes this an idempotent reconciliation, never a
                // second mutation.
                if attempts.is_multiple_of(40) {
                    match client.request(request.clone()).await {
                        Ok(Ok(response)) => return Ok(response),
                        Ok(Err(rejection)) => initial_rejection = Some(rejection.to_string()),
                        Err(_) => {}
                    }
                }
                let _ = error;
            }
            Err(_) => {}
        }
        attempts = attempts.wrapping_add(1);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

fn is_provider_revision(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(not(test))]
async fn apply_security_wizard_via_daemon(_cwd: &std::path::Path, run: &WizardRun) -> Result<bool> {
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for security setup")?;
    let project_root = global_config_dir()
        .context("resolving global config for security setup")?
        .display()
        .to_string();
    let snapshot_session_id = uuid::Uuid::new_v4().to_string();
    let response = daemon
        .client
        .request(Request::GetExtendedConfigSnapshot {
            project_root: project_root.clone(),
            snapshot_session_id: snapshot_session_id.clone(),
        })
        .await?
        .map_err(|error| anyhow!("daemon rejected security settings snapshot: {error}"))?;
    let Response::ExtendedConfigSnapshot { layers, .. } = response else {
        bail!("daemon returned unexpected security settings snapshot: {response:?}");
    };
    let layer = layers
        .into_iter()
        .last()
        .context("daemon returned no writable security settings layer")?;
    let mut operations = Vec::new();
    if let Some(value) = cockpit_core::wizard::sandbox_mode_answer(run)
        && value != layer.config.sandbox.default_mode
    {
        operations.push(cockpit_proto::ExtendedConfigPathMutation::Set {
            path: vec!["sandbox".into(), "default_mode".into()],
            value: serde_json::to_value(value)?,
        });
    }
    if let Some(value) = cockpit_core::wizard::approval_mode_answer(run)
        && value != layer.config.default_approval_mode
    {
        operations.push(cockpit_proto::ExtendedConfigPathMutation::Set {
            path: vec!["default_approval_mode".into()],
            value: serde_json::to_value(value)?,
        });
    }
    if let Some(value) = cockpit_core::wizard::min_secret_length_answer(run)
        && value != layer.config.redact.min_secret_length
    {
        operations.push(cockpit_proto::ExtendedConfigPathMutation::Set {
            path: vec!["redact".into(), "min_secret_length".into()],
            value: serde_json::to_value(value)?,
        });
    }
    if operations.is_empty() {
        return Ok(false);
    }
    let denylist = layer
        .denylist
        .iter()
        .map(|entry| cockpit_proto::DesiredDenylistEntry::Existing {
            entry_id: entry.entry_id.clone(),
        })
        .collect();
    let patch = cockpit_proto::ExtendedConfigPatch {
        operations,
        materialize: false,
        denylist,
        redacted_mutations: Vec::new(),
    };
    let mutation_intent_hash = patch
        .sanitized_intent_hash()
        .context("identifying security settings mutation")?;
    let client_operation_id = uuid::Uuid::new_v4().to_string();
    let response = request_durable_local_mutation(
        &daemon.client,
        &client_operation_id,
        "apply_extended_config_patch",
        Request::ApplyExtendedConfigPatch {
            client_operation_id: client_operation_id.clone(),
            project_root,
            layer_id: layer.layer_id.clone(),
            patch,
            expected_revision: layer.revision.clone(),
            snapshot_session_id,
        },
    )
    .await?;
    match response {
        Response::ExtendedConfigSaved {
            client_operation_id: returned_operation_id,
            mutation_intent_hash: returned_intent_hash,
            layer_id,
            consumed_revision,
            status: cockpit_proto::ConfigCommitStatus::Committed,
            ..
        } if returned_operation_id == client_operation_id
            && returned_intent_hash == mutation_intent_hash
            && layer_id == layer.layer_id
            && consumed_revision == layer.revision =>
        {
            Ok(true)
        }
        other => bail!("daemon returned an unbound security settings receipt: {other:?}"),
    }
}

#[cfg(not(test))]
fn provider_view_entry_for_edit(
    view: &cockpit_proto::ProviderEntryView,
) -> cockpit_config::config::providers::ProviderEntry {
    let mut entry = view.entry.clone();
    entry.headers = view
        .headers
        .iter()
        .map(|header| cockpit_config::config::providers::HeaderSpec {
            name: header.name.clone(),
            value: "********".into(),
        })
        .collect();
    entry
}

fn provider_view_matches_entry(
    view: &cockpit_proto::ProviderEntryView,
    expected: &cockpit_config::config::providers::ProviderEntry,
) -> bool {
    let expected_headers = expected.headers.clone();
    let mut expected = expected.clone();
    expected.url = cockpit_proto::redact_url_for_owner_view(&expected.url);
    expected.credential_ref = None;
    expected.headers.clear();
    serde_json::to_value(expected).ok() == serde_json::to_value(&view.entry).ok()
        && view.headers.len() == expected_headers.len()
        && view
            .headers
            .iter()
            .zip(&expected_headers)
            .all(|(actual, wanted)| {
                actual.redacted && actual.name.eq_ignore_ascii_case(&wanted.name)
            })
}

#[cfg(not(test))]
async fn apply_model_wizard_via_daemon(
    _cwd: &std::path::Path,
    run: &WizardRun,
) -> Result<(bool, bool, Option<String>)> {
    use cockpit_config::config::providers::{ActiveModelRef, CapabilityStatus};

    let (provider_id, model_id) =
        cockpit_core::wizard::model_ref_answer(run).context("model answer")?;
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for model setup")?;
    let snapshot_session_id = uuid::Uuid::new_v4().to_string();
    let response = daemon
        .client
        .request(Request::GetProviderCatalogSnapshot {
            project_root: global_config_dir()
                .context("resolving global config for model setup")?
                .display()
                .to_string(),
            provider_id: Some(provider_id.clone()),
            snapshot_session_id: snapshot_session_id.clone(),
        })
        .await?
        .map_err(|error| anyhow!("daemon rejected model settings snapshot: {error}"))?;
    let Response::ProviderCatalogSnapshot {
        config,
        snapshot_session_id: returned_session_id,
        layer_id,
        owner_root,
        base_revision,
        config_generation: consumed_config_generation,
        ..
    } = response
    else {
        bail!("daemon returned unexpected model settings snapshot: {response:?}");
    };
    if returned_session_id != snapshot_session_id {
        bail!("daemon returned an unbound model settings snapshot");
    }
    let provider_view = config
        .providers
        .get(&provider_id)
        .with_context(|| format!("provider `{provider_id}` not found"))?;
    let mut entry = provider_view_entry_for_edit(provider_view);
    let model = entry
        .models
        .iter_mut()
        .find(|model| model.id == model_id)
        .with_context(|| format!("model `{provider_id}:{model_id}` not found"))?;
    let before = serde_json::to_value(&*model)?;
    if let Some(value) = cockpit_core::wizard::model_trust_answer(run) {
        model.trust = Some(value);
    }
    let capabilities = cockpit_core::wizard::model_capability_answers(run);
    let status = |name: &str| {
        Some(if capabilities.contains(name) {
            CapabilityStatus::Supported
        } else {
            CapabilityStatus::Unsupported
        })
    };
    model.capability_overrides.image_input = status("images");
    model.capability_overrides.tool_calling = status("tools");
    model.capability_overrides.reasoning = status("reasoning");
    model.capability_overrides.structured_outputs = status("structured_outputs");
    model.capability_overrides.context_tokens =
        cockpit_core::wizard::model_context_tokens_answer(run);
    model.capability_overrides.max_output_tokens =
        cockpit_core::wizard::model_max_output_tokens_answer(run);
    if let Some(value) = cockpit_core::wizard::model_default_thinking_answer(run) {
        model.default_thinking_mode = value;
    }
    let subagent = cockpit_core::wizard::model_subagent_answers(run);
    model.subagent_invokable = Some(subagent.contains("subagent_invokable"));
    model.can_delegate = Some(subagent.contains("can_delegate"));
    if let Some(value) = cockpit_core::wizard::model_system_prompt_answer(run) {
        model.system_prompt = value;
    }
    let model_changed = before != serde_json::to_value(&*model)?;
    let active_model =
        cockpit_core::wizard::model_make_default_answer(run).then(|| ActiveModelRef {
            provider: provider_id.clone(),
            model: model_id.clone(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        });
    let default_changed = active_model
        .as_ref()
        .is_some_and(|next| config.active_model.as_ref() != Some(next));
    if !model_changed && !default_changed {
        return Ok((false, false, None));
    }
    let expected_entry = entry.clone();
    let mutation = cockpit_proto::ProviderMutationBatch {
        upserts: model_changed
            .then(|| cockpit_proto::ProviderMutationUpsert {
                provider_id: provider_id.clone(),
                header_secrets: vec![None; entry.headers.len()],
                entry,
            })
            .into_iter()
            .collect(),
        deletes: Vec::new(),
        metadata: default_changed.then(|| cockpit_proto::ProviderLayerMetadataPatch {
            category_defaults: config.category_defaults.clone(),
            on_unlisted_models_fetch: config
                .on_unlisted_models_fetch
                .unwrap_or(crate::config::providers::OnUnlistedModelsFetch::Keep),
            active_model: active_model.clone(),
        }),
    };
    let mutation_intent_hash = mutation
        .sanitized_intent_hash()
        .context("identifying model settings mutation")?;
    let client_operation_id = uuid::Uuid::new_v4().to_string();
    let response = request_durable_local_mutation(
        &daemon.client,
        &client_operation_id,
        "apply_provider_mutation",
        Request::ApplyProviderMutation {
            snapshot_session_id: snapshot_session_id.clone(),
            layer_id: layer_id.clone(),
            expected_revision: base_revision.clone(),
            client_operation_id: client_operation_id.clone(),
            mutation_intent_hash: mutation_intent_hash.clone(),
            mutation,
        },
    )
    .await?;
    match response {
        Response::ProviderMutationCommitted {
            client_operation_id: returned_operation_id,
            snapshot_session_id: returned_session_id,
            layer_id: returned_layer_id,
            owner_root: returned_owner_root,
            mutation_intent_hash: returned_intent_hash,
            consumed_revision,
            result_revision,
            config_generation,
            config: result,
            status: cockpit_proto::ConfigCommitStatus::Committed,
            publication: cockpit_proto::ConfigPublicationStatus::Published,
            ..
        } if returned_operation_id == client_operation_id
            && returned_session_id == snapshot_session_id
            && returned_layer_id == layer_id
            && returned_owner_root == owner_root
            && returned_intent_hash == mutation_intent_hash
            && consumed_revision == base_revision
            && is_provider_revision(&result_revision)
            && result_revision != consumed_revision
            && config_generation == consumed_config_generation.saturating_add(1)
            && (!model_changed
                || result
                    .providers
                    .get(&provider_id)
                    .is_some_and(|view| provider_view_matches_entry(view, &expected_entry)))
            && (!default_changed || result.active_model == active_model) =>
        {
            Ok((
                true,
                model_changed,
                default_changed.then(|| "daemon-selected layer".to_string()),
            ))
        }
        other => bail!("daemon returned an unbound model settings receipt: {other:?}"),
    }
}

struct ProviderSetupActions {
    cwd: PathBuf,
    headers: Vec<HeaderSpec>,
    saved: Option<(String, PathBuf)>,
    security_saved: Option<PathBuf>,
    model_saved: Option<PathBuf>,
    host_capabilities: Option<cockpit_proto::HostCapabilitySnapshot>,
}

impl ProviderSetupActions {
    fn new(cwd: PathBuf) -> Self {
        Self {
            cwd,
            headers: Vec::new(),
            saved: None,
            security_saved: None,
            model_saved: None,
            host_capabilities: None,
        }
    }

    fn with_host_capabilities(mut self, snapshot: cockpit_proto::HostCapabilitySnapshot) -> Self {
        self.host_capabilities = Some(snapshot);
        self
    }

    async fn handle_action(
        &mut self,
        step_id: &'static str,
        run: &WizardRun,
        io: &mut dyn TerminalIo,
    ) -> Result<()> {
        match step_id {
            "headers" => {
                let template =
                    selected_provider_template(run).context("provider template answer")?;
                self.headers = crate::providers::default_headers_for(template);
                if self.headers.is_empty() {
                    io.write_line("No default headers for this provider.")?;
                } else {
                    io.write_line("Using the provider template's default headers.")?;
                }
            }
            "copilot-auth" => {
                io.write_line(
                    "Set GH_TOKEN, GITHUB_TOKEN, or COPILOT_GITHUB_TOKEN before using this provider.",
                )?;
                let template =
                    selected_provider_template(run).context("provider template answer")?;
                self.headers = crate::providers::default_headers_for(template);
            }
            "grok-oauth" => {
                require_oauth_acknowledgement("grok-oauth", io).await?;
                io.write_line("Starting Grok OAuth login.")?;
                let (flow_id, authorize_url, _) =
                    begin_provider_oauth_via_daemon("grok-oauth").await?;
                io.write_line("Open this URL and approve access:")?;
                io.write_line(&authorize_url)?;
                if !crate::sysinfo::is_ssh() {
                    let _ = crate::browser::open(&authorize_url);
                }
                io.write("Paste the callback URL or code: ")?;
                let input = io.read_line().context("reading Grok OAuth callback")?;
                complete_provider_oauth_via_daemon(flow_id, Some(input.trim().to_string())).await?;
                io.write_line("Grok OAuth login complete.")?;
            }
            "codex-oauth" => {
                require_oauth_acknowledgement("codex-oauth", io).await?;
                io.write_line("Starting Codex device-code login.")?;
                let (flow_id, authorize_url, user_code) =
                    begin_provider_oauth_via_daemon("codex-oauth").await?;
                io.write_line(&authorize_url)?;
                io.write_line(&format!("Enter code: {}", user_code.unwrap_or_default()))?;
                if !crate::sysinfo::is_ssh() {
                    let _ = crate::browser::open(&authorize_url);
                }
                complete_provider_oauth_via_daemon(flow_id, None).await?;
                io.write_line("Codex OAuth login complete.")?;
            }
            "saving" => {
                self.save_provider(run, io).await?;
            }
            "fetching" => {
                self.fetch_models(io).await?;
            }
            "test-key" => {
                self.test_key(io).await?;
            }
            "security-save" => {
                #[cfg(test)]
                let result = cockpit_core::wizard::apply_security_answers_with_caps(
                    &self.cwd,
                    run,
                    self.host_capabilities.as_ref(),
                )?
                .map(|_| true)
                .unwrap_or(false);
                #[cfg(not(test))]
                let result = apply_security_wizard_via_daemon(&self.cwd, run).await?;
                if result {
                    self.security_saved = Some(global_config_file()?);
                    io.write_line("Saved security settings through the daemon.")?;
                } else {
                    io.write_line("Security settings unchanged.")?;
                }
            }
            "model-save" => {
                #[cfg(test)]
                let (changed, model_file_written, default_scope) = {
                    let outcome = cockpit_core::wizard::apply_model_answers(&self.cwd, run)?;
                    (
                        !outcome.changed_nothing(),
                        outcome.model_file.is_some(),
                        outcome.default_scope,
                    )
                };
                #[cfg(not(test))]
                let (changed, model_file_written, default_scope) =
                    apply_model_wizard_via_daemon(&self.cwd, run).await?;
                if model_file_written {
                    self.model_saved = Some(global_config_file()?);
                    io.write_line("Saved model settings through the daemon.")?;
                }
                if let Some(scope) = default_scope {
                    io.write_line(&format!(
                        "Set the default model for new sessions in this configuration context ({scope}). Sessions that already exist keep their own saved model."
                    ))?;
                }
                if !changed {
                    io.write_line("Model settings unchanged.")?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn save_provider(&mut self, run: &WizardRun, io: &mut dyn TerminalIo) -> Result<()> {
        let id = provider_id_answer(run).context("provider id answer")?;
        let headers = provider_headers_for_answers(run, &self.headers)?;
        let mut entry = provider_entry_from_answers(run, headers).context("provider answers")?;
        let daemon = ensure_persistent_daemon()
            .await
            .context("starting persistent daemon for provider setup")?;
        // The daemon stages vault bytes and the reference-only config entry
        // under one recoverable journal.  The CLI never allocates predictable
        // vault names or performs a secret/config two-step.
        let header_reference_notice = env_var_reference_notice(&entry.headers);
        let header_secrets = entry
            .headers
            .iter_mut()
            .map(|header| {
                let value = header.value.trim();
                // Only literal secret material is owner-remoted. A structurally
                // valid deferred reference (`$secret:…`, `$VAR`, `Bearer $VAR`,
                // or public protocol metadata) must stay verbatim in config —
                // extracting an env-var reference would replace it with an
                // opaque `$secret:` vault entry and break the provider's auth.
                // Mirrors the TUI's `upsert_provider_config_via_daemon` gate.
                let is_secret = !value.is_empty()
                    && !crate::config::providers::is_safe_provider_header_reference(
                        &header.name.to_ascii_lowercase(),
                        value,
                    );
                is_secret.then(|| {
                    cockpit_proto::ProviderSecretValue::new(std::mem::take(&mut header.value))
                })
            })
            .collect::<Vec<_>>();
        let snapshot_session_id = uuid::Uuid::new_v4().to_string();
        let snapshot = daemon
            .client
            .request(Request::GetProviderCatalogSnapshot {
                project_root: global_config_dir()
                    .context("resolving global config for provider setup")?
                    .display()
                    .to_string(),
                // A first-time provider has no catalog row to filter by. The
                // full layer snapshot still issues the exact CAS capability
                // needed for an add or replacement.
                provider_id: None,
                snapshot_session_id: snapshot_session_id.clone(),
            })
            .await?
            .map_err(|error| anyhow!("daemon rejected provider catalog snapshot: {error}"))?;
        let Response::ProviderCatalogSnapshot {
            snapshot_session_id: returned_session_id,
            layer_id,
            owner_root,
            base_revision,
            config_generation: consumed_config_generation,
            ..
        } = snapshot
        else {
            bail!("daemon returned unexpected provider catalog snapshot: {snapshot:?}");
        };
        if returned_session_id != snapshot_session_id {
            bail!("daemon returned an unbound provider catalog snapshot");
        }
        let expected_entry = entry.clone();
        let mutation = cockpit_proto::ProviderMutationBatch {
            upserts: vec![cockpit_proto::ProviderMutationUpsert {
                provider_id: id.clone(),
                entry,
                header_secrets,
            }],
            deletes: Vec::new(),
            metadata: None,
        };
        let mutation_intent_hash = mutation
            .sanitized_intent_hash()
            .context("identifying provider configuration mutation")?;
        let client_operation_id = uuid::Uuid::new_v4().to_string();
        let response = request_durable_local_mutation(
            &daemon.client,
            &client_operation_id,
            "apply_provider_mutation",
            Request::ApplyProviderMutation {
                snapshot_session_id: snapshot_session_id.clone(),
                layer_id: layer_id.clone(),
                expected_revision: base_revision.clone(),
                client_operation_id: client_operation_id.clone(),
                mutation_intent_hash: mutation_intent_hash.clone(),
                mutation,
            },
        )
        .await?;
        match response {
            Response::ProviderMutationCommitted {
                client_operation_id: returned_operation_id,
                snapshot_session_id: returned_session_id,
                layer_id: returned_layer_id,
                owner_root: returned_owner_root,
                mutation_intent_hash: returned_intent_hash,
                consumed_revision,
                result_revision,
                config_generation,
                config,
                status: cockpit_proto::ConfigCommitStatus::Committed,
                publication: cockpit_proto::ConfigPublicationStatus::Published,
                ..
            } if returned_operation_id == client_operation_id
                && returned_session_id == snapshot_session_id
                && returned_layer_id == layer_id
                && returned_owner_root == owner_root
                && returned_intent_hash == mutation_intent_hash
                && consumed_revision == base_revision
                && is_provider_revision(&result_revision)
                && result_revision != consumed_revision
                && config_generation == consumed_config_generation.saturating_add(1)
                && config
                    .providers
                    .get(&id)
                    .is_some_and(|view| provider_view_matches_entry(view, &expected_entry)) => {}
            other => bail!("daemon returned an unbound provider configuration receipt: {other:?}"),
        }
        self.saved = Some((id.clone(), global_config_file()?));
        io.write_line(&format!("Saved provider `{id}`."))?;
        if let Some(message) = header_reference_notice {
            io.write_line(&message)?;
        }
        Ok(())
    }

    async fn test_key(&mut self, io: &mut dyn TerminalIo) -> Result<()> {
        let Some((id, _)) = self.saved.clone() else {
            return Ok(());
        };
        let daemon = ensure_persistent_daemon()
            .await
            .context("starting persistent daemon for provider test")?;
        let response = daemon
            .client
            .request(Request::FetchProviderModels {
                project_root: self.cwd.display().to_string(),
                provider_id: Some(id.clone()),
                model_id: None,
                deep: false,
                on_unlisted: None,
                allow_fallback: false,
            })
            .await?
            .map_err(|error| anyhow!("daemon rejected provider key test: {error}"))?;
        let Response::ProviderModelsFetched { results, .. } = response else {
            bail!("daemon returned unexpected provider key test response: {response:?}");
        };
        let outcome = results.into_iter().next().map(|result| result.outcome);
        match outcome {
            Some(crate::daemon::proto::ProviderModelFetchOutcome::Models { models, .. }) => {
                io.write_line(&format!("key verified · {} models", models.len()))?
            }
            Some(crate::daemon::proto::ProviderModelFetchOutcome::Unsupported) => {
                io.write_line("key test unavailable: provider does not support model discovery")?
            }
            Some(crate::daemon::proto::ProviderModelFetchOutcome::UnlistedModelsPreview {
                unlisted_count,
            }) => io.write_line(&format!(
                "Model fetch needs a keep/remove decision for {unlisted_count} configured model(s)."
            ))?,
            Some(crate::daemon::proto::ProviderModelFetchOutcome::FallbackAvailable {
                reason,
                ..
            }) => io.write_line(&format!("Model fetch fallback available: {reason}"))?,
            Some(crate::daemon::proto::ProviderModelFetchOutcome::Error { message }) => {
                io.write_line(&format!("key test failed: {message}"))?
            }
            None => io.write_line("key test failed: daemon returned no provider result")?,
        }
        Ok(())
    }

    async fn fetch_models(&mut self, io: &mut dyn TerminalIo) -> Result<()> {
        self.test_key(io).await?;
        Ok(())
    }
}

async fn begin_provider_oauth_via_daemon(
    provider_id: &str,
) -> Result<(String, String, Option<String>)> {
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for OAuth login")?;
    match daemon
        .client
        .request(Request::BeginProviderOAuth {
            client_operation_id: uuid::Uuid::new_v4().to_string(),
            provider_id: provider_id.to_string(),
        })
        .await?
    {
        Ok(Response::ProviderOAuthStarted {
            flow_id,
            authorize_url,
            user_code,
            ..
        }) => Ok((flow_id, authorize_url, user_code)),
        Ok(other) => bail!("daemon returned unexpected OAuth begin response: {other:?}"),
        Err(error) => bail!("daemon rejected OAuth begin: {error}"),
    }
}

async fn complete_provider_oauth_via_daemon(flow_id: String, input: Option<String>) -> Result<()> {
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for OAuth login")?;
    match daemon
        .client
        .request(Request::CompleteProviderOAuth {
            client_operation_id: uuid::Uuid::new_v4().to_string(),
            flow_id,
            input: input.map(cockpit_proto::SensitiveWirePayload::new),
        })
        .await?
    {
        Ok(Response::ProviderOAuthCompleted {
            logged_in: true, ..
        }) => Ok(()),
        Ok(other) => bail!("daemon returned unexpected OAuth completion response: {other:?}"),
        Err(error) => bail!("daemon rejected OAuth completion: {error}"),
    }
}

fn provider_headers_for_answers(
    run: &WizardRun,
    advanced_headers: &[HeaderSpec],
) -> Result<Vec<HeaderSpec>> {
    let template = selected_provider_template(run).context("provider template answer")?;
    match run.answer("auth-method") {
        Some(WizardAnswer::Select(value)) if value == "paste-key" => {
            let WizardAnswer::Secret(key) = run.answer("api-key").context("api key answer")? else {
                bail!("api key answer must be secret");
            };
            Ok(crate::providers::headers_for_pasted_key(template, key))
        }
        Some(WizardAnswer::Select(value)) if value == "env-var" => {
            let WizardAnswer::Text(env_var) = run
                .answer("env-var")
                .context("environment variable answer")?
            else {
                bail!("environment variable answer must be text");
            };
            Ok(crate::providers::headers_for_env_var(template, env_var))
        }
        _ => Ok(advanced_headers.to_vec()),
    }
}

fn env_var_reference_notice(headers: &[HeaderSpec]) -> Option<String> {
    // Setup is a daemon client.  Inspecting process environment values here
    // would make the CLI a second secret resolver; syntax metadata is enough
    // to remind the user which variables the daemon will resolve later.
    let mut referenced = Vec::new();
    for header in headers {
        for name in cockpit_core::envref::referenced_names(&header.value) {
            if !name.starts_with("secret:") && !referenced.contains(&name) {
                referenced.push(name);
            }
        }
    }
    if referenced.is_empty() {
        None
    } else {
        Some(format!(
            "Environment variable reference detected; make sure to set it before use: {}",
            referenced.join(", ")
        ))
    }
}

impl TerminalActionHandler for ProviderSetupActions {
    fn run_action<'a>(
        &'a mut self,
        step_id: &'static str,
        run: &'a WizardRun,
        io: &'a mut dyn TerminalIo,
    ) -> ActionFuture<'a> {
        Box::pin(self.handle_action(step_id, run, io))
    }
}

fn subscription_oauth_provider(step_id: &str) -> Option<&'static str> {
    match step_id {
        "codex-oauth" => Some(crate::auth::subscription_ack::CODEX_OAUTH_PROVIDER),
        "grok-oauth" => Some(crate::auth::subscription_ack::GROK_OAUTH_PROVIDER),
        _ => None,
    }
}

async fn require_oauth_acknowledgement(step_id: &str, io: &mut dyn TerminalIo) -> Result<()> {
    let Some(provider) = subscription_oauth_provider(step_id) else {
        return Ok(());
    };
    require_subscription_oauth_acknowledgement(provider, io).await
}

async fn require_subscription_oauth_acknowledgement(
    provider: &str,
    io: &mut dyn TerminalIo,
) -> Result<()> {
    // This marker is deliberately a daemon-owned named secret.  The setup
    // client only needs existence metadata (not its value), so it can make the
    // acknowledgement decision without opening a vault or DB locally.
    let name = format!("subscription-oauth-ack:{provider}");
    let daemon = ensure_persistent_daemon()
        .await
        .context("starting persistent daemon for subscription acknowledgement")?;
    let mut cursor = None;
    let mut restarts = 0;
    let already_acknowledged = loop {
        let response = daemon
            .client
            .request(Request::ListSecretInventory {
                cursor: cursor.clone(),
                limit: Some(cockpit_core::daemon::proto::MAX_OWNER_INVENTORY_PAGE_ENTRIES as u16),
            })
            .await?;
        let response = match response {
            Ok(response) => response,
            Err(error)
                if error.code == cockpit_core::daemon::proto::ErrorCode::Conflict
                    && restarts < 2 =>
            {
                // A concurrent owner mutation invalidates the cursor. Restart
                // the bounded traversal so setup never silently misses an ack.
                restarts += 1;
                cursor = None;
                continue;
            }
            Err(error) => bail!("daemon rejected subscription acknowledgement lookup: {error}"),
        };
        let Response::SecretInventory {
            entries,
            next_cursor,
        } = response
        else {
            bail!("daemon returned unexpected acknowledgement lookup response")
        };
        if inventory_contains_subscription_ack(&entries, &name) {
            break true;
        }
        let Some(next_cursor) = next_cursor else {
            break false;
        };
        cursor = Some(next_cursor);
    };
    if already_acknowledged {
        return Ok(());
    }

    io.write_line(crate::auth::subscription_ack::ACKNOWLEDGEMENT_TEXT)?;
    io.write("Type `I acknowledge` to continue: ")?;
    let response = io
        .read_line()
        .context("reading subscription OAuth acknowledgement")?;
    if response.trim().eq_ignore_ascii_case("I acknowledge") {
        // Stable across process restarts so rerunning setup replays the exact
        // durable acknowledgement after a lost response.
        let client_operation_id = format!("setup-subscription-ack-{provider}");
        match daemon
            .client
            .request(Request::PutSubscriptionAck {
                client_operation_id: client_operation_id.clone(),
                provider_id: provider.to_string(),
            })
            .await?
        {
            Ok(Response::SubscriptionAckCommitted {
                client_operation_id: returned_id,
                provider_id,
                request_hash,
                ..
            }) if returned_id == client_operation_id
                && provider_id == provider
                && request_hash.len() == 64 => {}
            Ok(other) => {
                bail!("daemon returned unexpected acknowledgement store response: {other:?}")
            }
            Err(error) => bail!("daemon rejected subscription acknowledgement store: {error}"),
        }
        return Ok(());
    }

    bail!(
        "subscription OAuth login requires acknowledgement; run `cockpit setup` interactively and type `I acknowledge` to continue"
    )
}

fn inventory_contains_subscription_ack(entries: &[SecretInventoryEntry], name: &str) -> bool {
    entries
        .iter()
        .any(|entry| entry.kind == SecretInventoryKind::SubscriptionAck && entry.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::dirs::COCKPIT_CONFIG_ENV;

    #[derive(Default)]
    struct ScriptIo {
        input: std::collections::VecDeque<String>,
        output: String,
        reads: usize,
        writes: usize,
    }

    impl ScriptIo {
        fn new(lines: &[&str]) -> Self {
            Self {
                input: lines.iter().map(|line| format!("{line}\n")).collect(),
                ..Default::default()
            }
        }
    }

    impl TerminalIo for ScriptIo {
        fn read_line(&mut self) -> io::Result<String> {
            self.reads += 1;
            self.input.pop_front().ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "scripted input exhausted")
            })
        }

        fn write(&mut self, text: &str) -> io::Result<()> {
            self.writes += 1;
            self.output.push_str(text);
            Ok(())
        }
    }

    #[derive(Default)]
    struct TestActions {
        saved: Option<(String, String)>,
        fetches: usize,
        headers: Vec<HeaderSpec>,
    }

    impl TerminalActionHandler for TestActions {
        fn run_action<'a>(
            &'a mut self,
            step_id: &'static str,
            run: &'a WizardRun,
            io: &'a mut dyn TerminalIo,
        ) -> ActionFuture<'a> {
            Box::pin(async move {
                match step_id {
                    "headers" => {
                        let template =
                            selected_provider_template(run).context("provider template")?;
                        self.headers = crate::providers::default_headers_for(template);
                        io.write_line("headers accepted")?;
                    }
                    "saving" => {
                        let id = provider_id_answer(run).context("provider id")?;
                        let entry = provider_entry_from_answers(run, self.headers.clone())
                            .context("provider entry")?;
                        self.saved = Some((id, entry.url));
                        io.write_line("saved")?;
                    }
                    "fetching" => {
                        self.fetches += 1;
                        io.write_line("fetched")?;
                    }
                    _ => {}
                }
                Ok(())
            })
        }
    }

    struct CockpitConfigEnvGuard {
        // Ordering matters: `_daemon` (the in-process auto-promote guard) is
        // declared before `_guard` so it drops first, tearing the promoted
        // daemon down while the process-global env lock is still held.
        _daemon: cockpit_core::daemon::InProcessAutoPromoteGuard,
        _guard: crate::test_env::TestEnvGuard,
    }

    impl CockpitConfigEnvGuard {
        async fn set_async(path: &std::path::Path) -> Self {
            Self::set_with_state_async(
                path,
                path.parent()
                    .unwrap_or_else(|| std::path::Path::new("/tmp")),
            )
            .await
        }

        async fn set_with_state_async(
            path: &std::path::Path,
            state_home: &std::path::Path,
        ) -> Self {
            let guard = crate::test_env::lock_async().await;
            // Production config publication locks the COCKPIT_CONFIG parent and
            // its `providers/` catalog no-follow. Materialize that tree so the
            // isolated owner can snapshot without waiting on a missing path.
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("create isolated config directory");
                std::fs::create_dir_all(parent.join("providers"))
                    .expect("create isolated provider catalog directory");
            }
            if !path.exists() {
                std::fs::write(path, "{}\n").expect("write isolated config stub");
            }
            std::fs::create_dir_all(state_home).expect("create isolated state home");
            let home = state_home.join("home");
            let xdg_config = state_home.join("xdg-config");
            std::fs::create_dir_all(&home).expect("create isolated home");
            std::fs::create_dir_all(&xdg_config).expect("create isolated XDG config");
            guard.set_var(COCKPIT_CONFIG_ENV, path);
            guard.set_var("HOME", &home);
            guard.set_var("XDG_CONFIG_HOME", &xdg_config);
            guard.set_var("XDG_STATE_HOME", state_home);
            guard.set_var("XDG_DATA_HOME", state_home);
            // Isolate the daemon socket/runtime namespace so `ensure_persistent_
            // daemon()` never discovers a real user daemon and the in-process
            // promotion binds an isolated canonical path.
            let runtime_dir = state_home.join("runtime");
            std::fs::create_dir_all(&runtime_dir).expect("create isolated runtime directory");
            guard.set_var("XDG_RUNTIME_DIR", &runtime_dir);
            guard.set_var("COCKPIT_TEST_NO_KEYRING", "1");
            // Setup/provider paths now route every secret and config write
            // through the owner-remoted daemon. Promote an in-process daemon
            // (production layered config source) so those RPCs resolve against
            // an isolated in-memory owner instead of timing out on a real
            // socket. Booting is lazy: tests that never call the daemon pay
            // nothing.
            let daemon =
                cockpit_core::daemon::enable_in_process_auto_promote_with_production_config();
            Self {
                _daemon: daemon,
                _guard: guard,
            }
        }
    }

    /// Seed workspace trust in the auto-promoted daemon for `root`. Provider
    /// config/secret writes are owner-remoted and fail closed on an untrusted
    /// workspace, exactly as in production; a real user trusts the workspace
    /// once before setup can persist. Trust is DB-owned by the daemon, so it
    /// must be set through the RPC — a local runtime-policy override would not
    /// reach the daemon's authoritative check.
    async fn trust_workspace_via_daemon(root: &std::path::Path) {
        let daemon = ensure_persistent_daemon()
            .await
            .expect("attach in-process daemon to seed workspace trust");
        let project_root = root.display().to_string();
        let expected_config_generation = match daemon
            .client
            .request(Request::GetWorkspaceTrust {
                project_root: project_root.clone(),
            })
            .await
            .expect("workspace trust read transport")
            .expect("workspace trust read response")
        {
            Response::WorkspaceTrust {
                config_generation, ..
            } => config_generation,
            other => panic!("unexpected workspace trust read: {other:?}"),
        };
        match daemon
            .client
            .request(Request::SetWorkspaceTrust {
                project_root,
                mode: cockpit_core::daemon::proto::WorkspaceTrustMode::Trust,
                expected_config_generation,
            })
            .await
            .expect("workspace trust set transport")
            .expect("workspace trust set response")
        {
            Response::WorkspaceTrustSet { .. } => {}
            other => panic!("unexpected workspace trust set: {other:?}"),
        }
    }

    /// Collect the daemon's redacted owner secret inventory. Setup persists
    /// every secret/ack through the owner, so verifying persistence goes
    /// through the same redacted read path production uses — the CLI never
    /// reads secret bytes back. The wire form carries names/kinds only; a
    /// broken persist leaves the entry absent, so presence is a real signal.
    async fn owner_secret_inventory() -> Vec<SecretInventoryEntry> {
        let daemon = ensure_persistent_daemon()
            .await
            .expect("attach in-process daemon to read owner inventory");
        let mut cursor = None;
        let mut collected = Vec::new();
        loop {
            let response = daemon
                .client
                .request(Request::ListSecretInventory {
                    cursor: cursor.clone(),
                    limit: Some(
                        cockpit_core::daemon::proto::MAX_OWNER_INVENTORY_PAGE_ENTRIES as u16,
                    ),
                })
                .await
                .expect("owner inventory transport")
                .expect("owner inventory response");
            let Response::SecretInventory {
                entries,
                next_cursor,
            } = response
            else {
                panic!("unexpected owner inventory response");
            };
            // The redacted inventory must never carry secret bytes.
            let wire = serde_json::to_string(&entries).expect("inventory serializes");
            collected.extend(entries);
            let Some(next) = next_cursor else {
                let _ = wire;
                break;
            };
            cursor = Some(next);
        }
        collected
    }

    /// Pull the `$secret:NAME` reference the daemon materialized into a config
    /// header. The daemon allocates the vault name (the CLI never picks a
    /// predictable one), so the reference is opaque and must be read from the
    /// written config rather than assumed.
    fn extract_secret_reference(raw: &str) -> Option<String> {
        let start = raw.find("$secret:")? + "$secret:".len();
        let name: String = raw[start..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
            .collect();
        (!name.is_empty()).then_some(name)
    }

    /// Assert a pasted provider secret was owner-remoted: the config header
    /// carries only a daemon-allocated `$secret:` reference (never the literal
    /// bytes), and the owner vault holds that exact named secret. Verified
    /// through the redacted owner inventory — the CLI never reads secret bytes.
    async fn assert_provider_secret_owned(provider_file: &std::path::Path, literal: &str) {
        let raw = std::fs::read_to_string(provider_file).expect("provider file");
        assert!(
            !raw.contains(literal),
            "config must not embed the literal provider secret: {raw}"
        );
        let name = extract_secret_reference(&raw)
            .unwrap_or_else(|| panic!("provider header must carry a $secret: reference: {raw}"));
        let inventory = owner_secret_inventory().await;
        assert!(
            inventory
                .iter()
                .any(|entry| entry.name == name && entry.kind == SecretInventoryKind::NamedSecret),
            "owner vault must hold the referenced secret `{name}`: {inventory:?}"
        );
        let wire = serde_json::to_string(&inventory).expect("inventory serializes");
        assert!(
            !wire.contains(literal),
            "owner inventory must not leak secret bytes"
        );
    }

    #[tokio::test]
    async fn codex_oauth_requires_acknowledgement() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.json");
        let state_home = tmp.path().join("state");
        let _env = CockpitConfigEnvGuard::set_with_state_async(&config_path, &state_home).await;
        let mut io = ScriptIo::new(&["no"]);

        let error = require_oauth_acknowledgement("codex-oauth", &mut io)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("requires acknowledgement"));
        assert!(io.output.contains("third-party client"));
        assert!(io.output.contains("may violate the provider terms"));
        assert!(io.output.contains("may result in account suspension"));
    }

    #[tokio::test]
    async fn grok_oauth_requires_acknowledgement() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.json");
        let state_home = tmp.path().join("state");
        let _env = CockpitConfigEnvGuard::set_with_state_async(&config_path, &state_home).await;
        let mut io = ScriptIo::new(&["no"]);

        let error = require_oauth_acknowledgement("grok-oauth", &mut io)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("requires acknowledgement"));
        assert!(io.output.contains("third-party client"));
        assert!(io.output.contains("may violate the provider terms"));
        assert!(io.output.contains("may result in account suspension"));
    }

    #[tokio::test]
    async fn acknowledgement_is_recorded_once() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.json");
        let state_home = tmp.path().join("state");
        let _env = CockpitConfigEnvGuard::set_with_state_async(&config_path, &state_home).await;
        let mut first = ScriptIo::new(&["I acknowledge"]);

        require_oauth_acknowledgement("codex-oauth", &mut first)
            .await
            .unwrap();
        // The acknowledgement is a daemon-owned named secret now, not an
        // on-disk marker the CLI writes. Verify it landed in the owner vault
        // through the same redacted inventory the production read path uses.
        let ack_name = format!(
            "subscription-oauth-ack:{}",
            crate::auth::subscription_ack::CODEX_OAUTH_PROVIDER
        );
        assert!(
            inventory_contains_subscription_ack(&owner_secret_inventory().await, &ack_name),
            "codex acknowledgement must be recorded in the owner vault"
        );
        assert_eq!(first.reads, 1);

        let mut second = ScriptIo::default();
        require_oauth_acknowledgement("codex-oauth", &mut second)
            .await
            .unwrap();
        assert_eq!(second.reads, 0);
        assert!(second.output.is_empty());

        let mut grok = ScriptIo::default();
        let error = require_oauth_acknowledgement("grok-oauth", &mut grok)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("reading subscription OAuth acknowledgement")
        );
        assert_eq!(grok.reads, 1);
    }

    #[test]
    fn api_key_setup_has_no_acknowledgement() {
        assert_eq!(subscription_oauth_provider("headers"), None);
        assert_eq!(subscription_oauth_provider("saving"), None);
        assert_eq!(subscription_oauth_provider("test-key"), None);
    }

    #[test]
    fn acknowledgement_lookup_requires_the_subscription_ack_kind() {
        let name = "subscription-oauth-ack:codex";
        let entries = vec![
            SecretInventoryEntry {
                name: name.into(),
                kind: SecretInventoryKind::NamedSecret,
                configured: true,
            },
            SecretInventoryEntry {
                name: name.into(),
                kind: SecretInventoryKind::CredentialRecord,
                configured: true,
            },
        ];
        assert!(!inventory_contains_subscription_ack(&entries, name));
        let mut entries = entries;
        entries.push(SecretInventoryEntry {
            name: name.into(),
            kind: SecretInventoryKind::SubscriptionAck,
            configured: true,
        });
        assert!(inventory_contains_subscription_ack(&entries, name));
    }

    #[tokio::test]
    async fn noninteractive_oauth_refuses_without_acknowledgement() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.json");
        let state_home = tmp.path().join("state");
        let _env = CockpitConfigEnvGuard::set_with_state_async(&config_path, &state_home).await;
        let mut io = ScriptIo::default();

        let error = require_oauth_acknowledgement("codex-oauth", &mut io)
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("reading subscription OAuth acknowledgement")
        );
        assert_eq!(io.reads, 1);
        assert!(io.output.contains("third-party client"));
    }

    fn write_model_wizard_provider(cwd: &std::path::Path) -> PathBuf {
        let path = most_specific_config_write_target(cwd)
            .unwrap_or_else(|| cwd.join(".cockpit").join(crate::config::dirs::CONFIG_FILE));
        let Some(parent) = path.parent() else {
            panic!("config target has no parent");
        };
        std::fs::create_dir_all(parent).unwrap();
        std::fs::write(&path, "{}").unwrap();
        let mut cfg = crate::config::providers::ProvidersConfig::default();
        let mut provider = crate::config::providers::ProviderEntry {
            url: "http://localhost:1/v1".to_string(),
            subagent_invokable: Some(true),
            can_delegate: Some(true),
            ..Default::default()
        };
        provider.models.push(crate::config::providers::ModelEntry {
            id: "m".to_string(),
            capabilities: crate::config::providers::ModelCapabilities {
                image_input: crate::config::providers::CapabilityStatus::Unsupported,
                ..Default::default()
            },
            ..Default::default()
        });
        cfg.providers.insert("p".to_string(), provider);
        let mut doc = ConfigDoc::load(&path).unwrap();
        doc.write(&cfg).unwrap();
        path
    }

    #[tokio::test]
    async fn model_wizard_terminal_end_to_end() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = CockpitConfigEnvGuard::set_async(&tmp.path().join("global-config.json")).await;
        write_model_wizard_provider(tmp.path());
        trust_workspace_via_daemon(tmp.path()).await;
        let descriptor = descriptor_for_cwd(crate::wizard::MODEL_WIZARD_ID, tmp.path()).unwrap();
        let mut io = ScriptIo::new(&[
            "p", "p:m", "frontier", "trusted", "images", "", "", "none", "y", "skip", "", "", "",
            "", "", "", "", "",
        ]);
        let mut actions = ProviderSetupActions::new(tmp.path().to_path_buf());

        let run = run_terminal_wizard(descriptor, &mut io, &true, &mut actions)
            .await
            .unwrap();

        assert!(run.is_complete());
        let cfg = ConfigDoc::load_effective(tmp.path());
        let provider = cfg.providers.get("p").unwrap();
        let model = provider
            .models
            .iter()
            .find(|model| model.id == "m")
            .unwrap();
        assert_eq!(
            model.trust,
            Some(crate::config::providers::ModelTrust::Trusted)
        );
        assert_eq!(
            model.capability_overrides.image_input,
            Some(crate::config::providers::CapabilityStatus::Supported)
        );
        assert_eq!(model.subagent_invokable, Some(false));
        assert_eq!(model.can_delegate, Some(false));
        assert_eq!(cfg.active_model.as_ref().unwrap().provider, "p");
        assert_eq!(cfg.active_model.as_ref().unwrap().model, "m");
        assert!(
            io.output
                .contains("Saved model settings through the daemon")
        );
    }

    #[tokio::test]
    async fn terminal_renderer_runs_provider_wizard() {
        let mut io = ScriptIo::new(&["openai", "", "", "advanced-headers", "skip-test"]);
        let mut actions = TestActions::default();

        let run = run_terminal_wizard(
            crate::wizard::provider_descriptor(),
            &mut io,
            &true,
            &mut actions,
        )
        .await
        .unwrap();

        assert!(run.is_complete());
        assert_eq!(
            actions.saved,
            Some((
                "openai".to_string(),
                "https://api.openai.com/v1".to_string()
            ))
        );
        assert_eq!(actions.fetches, 0);
        assert!(io.output.contains("Choose a provider template"));
    }

    #[tokio::test]
    async fn wizard_terminal_renderer_rejects_non_tty() {
        let mut io = ScriptIo::new(&["openai"]);
        let mut actions = TestActions::default();

        let err = run_terminal_wizard(
            crate::wizard::provider_descriptor(),
            &mut io,
            &false,
            &mut actions,
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("cockpit setup requires an interactive stdin")
        );
        assert_eq!(io.reads, 0);
        assert_eq!(io.writes, 0);
        assert!(actions.saved.is_none());
    }

    #[tokio::test]
    async fn terminal_renderer_back_navigation() {
        let mut io = ScriptIo::new(&[
            "openai",
            "back",
            "openai",
            "",
            "",
            "advanced-headers",
            "skip-test",
        ]);
        let mut actions = TestActions::default();

        let run = run_terminal_wizard(
            crate::wizard::provider_descriptor(),
            &mut io,
            &true,
            &mut actions,
        )
        .await
        .unwrap();

        assert!(run.is_complete());
        assert_eq!(
            actions.saved,
            Some((
                "openai".to_string(),
                "https://api.openai.com/v1".to_string()
            ))
        );
        assert!(
            io.output.matches("Choose a provider template").count() >= 2,
            "{}",
            io.output
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn paste_key_stores_secret_ref() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config_path = tmp.path().join("config/config.json");
        let state_home = tmp.path().join("state");
        let _env = CockpitConfigEnvGuard::set_with_state_async(&config_path, &state_home).await;
        trust_workspace_via_daemon(tmp.path()).await;
        let secret = "sk-provider-secret-abcdefghijklmnopqrstuvwxyz";
        let mut io = ScriptIo::new(&["openai", "", "", "", secret, "skip-test"]);
        let mut actions = ProviderSetupActions::new(tmp.path().to_path_buf());

        let run = run_terminal_wizard(
            crate::wizard::provider_descriptor(),
            &mut io,
            &true,
            &mut actions,
        )
        .await
        .unwrap();

        assert!(run.is_complete());
        let provider_path =
            crate::config::providers::provider_file_path_for_config(&config_path, "openai")
                .expect("provider path");
        // The secret is owner-remoted: the config header carries only a
        // daemon-allocated `$secret:` reference (never the literal), it lands
        // in the daemon vault (not a local `credentials.json`), and the CLI
        // never reads its bytes back — verified via the redacted owner
        // inventory.
        assert_provider_secret_owned(&provider_path, secret).await;
        assert!(
            !state_home.join("cockpit/credentials.json").exists(),
            "setup must persist through the vault, not credentials.json"
        );
        assert!(!io.output.contains(secret), "secret leaked in output");
        assert!(io.output.contains("Saved provider `openai`"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn nous_research_provider_wizard_materializes_secret_reference() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config_path = tmp.path().join("config/config.json");
        let state_home = tmp.path().join("state");
        let _env = CockpitConfigEnvGuard::set_with_state_async(&config_path, &state_home).await;
        trust_workspace_via_daemon(tmp.path()).await;
        let secret = "nr-provider-secret-abcdefghijklmnopqrstuvwxyz";
        // Explicit paste-key + skip-test so we never hit the network.
        let mut io = ScriptIo::new(&["nous-research", "", "", "paste-key", secret, "skip-test"]);
        let mut actions = ProviderSetupActions::new(tmp.path().to_path_buf());

        let run = run_terminal_wizard(
            crate::wizard::provider_descriptor(),
            &mut io,
            &true,
            &mut actions,
        )
        .await
        .expect("wizard completes");

        assert!(run.is_complete(), "output={}", io.output);
        let provider_path =
            crate::config::providers::provider_file_path_for_config(&config_path, "nous-research")
                .expect("provider path");
        let raw = std::fs::read_to_string(&provider_path).expect("provider file");
        assert!(
            raw.contains("https://inference-api.nousresearch.com/v1"),
            "{raw}"
        );
        assert_provider_secret_owned(&provider_path, secret).await;
        assert!(!state_home.join("cockpit/credentials.json").exists());
        assert!(!io.output.contains(secret), "secret leaked in output");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn baseten_provider_wizard_materializes_secret_reference() {
        let secret = "bt-provider-secret-abcdefghijklmnopqrstuvwxyz";
        {
            let tmp = tempfile::tempdir().expect("tempdir");
            let config_path = tmp.path().join("config/config.json");
            let state_home = tmp.path().join("state");
            let _env = CockpitConfigEnvGuard::set_with_state_async(&config_path, &state_home).await;
            trust_workspace_via_daemon(tmp.path()).await;
            let mut io = ScriptIo::new(&["baseten", "", "", "paste-key", secret, "skip-test"]);
            let mut actions = ProviderSetupActions::new(tmp.path().to_path_buf());
            let run = tokio::time::timeout(
                Duration::from_secs(30),
                run_terminal_wizard(
                    crate::wizard::provider_descriptor(),
                    &mut io,
                    &true,
                    &mut actions,
                ),
            )
            .await
            .unwrap_or_else(|_| panic!("paste-key wizard timed out; output={}", io.output))
            .expect("wizard completes");
            assert!(run.is_complete(), "output={}", io.output);
            let provider_path =
                crate::config::providers::provider_file_path_for_config(&config_path, "baseten")
                    .expect("provider path");
            let raw = std::fs::read_to_string(&provider_path).expect("provider file");
            assert!(raw.contains("https://inference.baseten.co/v1"), "{raw}");
            assert_provider_secret_owned(&provider_path, secret).await;
            assert!(!state_home.join("cockpit/credentials.json").exists());
            assert!(!io.output.contains(secret));
        }

        {
            let tmp2 = tempfile::tempdir().expect("tempdir");
            let config_path2 = tmp2.path().join("config/config.json");
            let state_home2 = tmp2.path().join("state");
            let _env2 =
                CockpitConfigEnvGuard::set_with_state_async(&config_path2, &state_home2).await;
            trust_workspace_via_daemon(tmp2.path()).await;
            let mut io2 =
                ScriptIo::new(&["baseten", "", "", "env-var", "BASETEN_API_KEY", "skip-test"]);
            let mut actions2 = ProviderSetupActions::new(tmp2.path().to_path_buf());
            tokio::time::timeout(
                Duration::from_secs(30),
                run_terminal_wizard(
                    crate::wizard::provider_descriptor(),
                    &mut io2,
                    &true,
                    &mut actions2,
                ),
            )
            .await
            .unwrap_or_else(|_| panic!("env-var wizard timed out; output={}", io2.output))
            .expect("env wizard");
            let raw2 = std::fs::read_to_string(
                crate::config::providers::provider_file_path_for_config(&config_path2, "baseten")
                    .expect("path"),
            )
            .expect("file");
            assert!(raw2.contains("Bearer $BASETEN_API_KEY"), "{raw2}");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn nous_research_provider_wizard_env_var_reference() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config_path = tmp.path().join("config/config.json");
        let state_home = tmp.path().join("state");
        let _env = CockpitConfigEnvGuard::set_with_state_async(&config_path, &state_home).await;
        trust_workspace_via_daemon(tmp.path()).await;
        let mut io = ScriptIo::new(&[
            "nous-research",
            "",
            "",
            "env-var",
            "NOUS_API_KEY",
            "skip-test",
        ]);
        let mut actions = ProviderSetupActions::new(tmp.path().to_path_buf());
        let run = run_terminal_wizard(
            crate::wizard::provider_descriptor(),
            &mut io,
            &true,
            &mut actions,
        )
        .await
        .expect("wizard completes");
        assert!(run.is_complete(), "output={}", io.output);
        let provider_path =
            crate::config::providers::provider_file_path_for_config(&config_path, "nous-research")
                .expect("provider path");
        let raw = std::fs::read_to_string(provider_path).expect("provider file");
        assert!(raw.contains("Bearer $NOUS_API_KEY"), "{raw}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn provider_add_terminal_end_to_end() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config_path = tmp.path().join("config/config.json");
        let state_home = tmp.path().join("state");
        let _env = CockpitConfigEnvGuard::set_with_state_async(&config_path, &state_home).await;
        trust_workspace_via_daemon(tmp.path()).await;
        let mut io = ScriptIo::new(&[
            "openai",
            "",
            "",
            "",
            "sk-provider-secret-abcdefghijklmnopqrstuvwxyz",
            "skip-test",
        ]);
        let mut actions = ProviderSetupActions::new(tmp.path().to_path_buf());

        let run = run_terminal_wizard(
            crate::wizard::provider_descriptor(),
            &mut io,
            &true,
            &mut actions,
        )
        .await
        .unwrap();

        assert!(run.is_complete());
        let provider_path =
            crate::config::providers::provider_file_path_for_config(&config_path, "openai")
                .expect("provider path");
        assert_provider_secret_owned(
            &provider_path,
            "sk-provider-secret-abcdefghijklmnopqrstuvwxyz",
        )
        .await;
        assert!(
            io.output
                .contains("key saved but unverified — it will be tested on your first message.")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn env_var_path_writes_var_ref() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config_path = tmp.path().join("config/config.json");
        let state_home = tmp.path().join("state");
        let _env = CockpitConfigEnvGuard::set_with_state_async(&config_path, &state_home).await;
        trust_workspace_via_daemon(tmp.path()).await;
        let mut io = ScriptIo::new(&["openai", "", "", "env-var", "OPENAI_API_KEY", "skip-test"]);
        let mut actions = ProviderSetupActions::new(tmp.path().to_path_buf());

        run_terminal_wizard(
            crate::wizard::provider_descriptor(),
            &mut io,
            &true,
            &mut actions,
        )
        .await
        .unwrap();

        let provider_path =
            crate::config::providers::provider_file_path_for_config(&config_path, "openai")
                .expect("provider path");
        let raw = std::fs::read_to_string(provider_path).expect("provider file");
        assert!(raw.contains("Bearer $OPENAI_API_KEY"), "{raw}");
        assert!(
            io.output
                .contains(
                    "Environment variable reference detected; make sure to set it before use: OPENAI_API_KEY"
                ),
            "{}",
            io.output
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wizard_skip_test_shows_unverified() {
        let mut io = ScriptIo::new(&["openai", "", "", "env-var", "OPENAI_API_KEY", "skip-test"]);
        let mut actions = TestActions::default();

        let run = run_terminal_wizard(
            crate::wizard::provider_descriptor(),
            &mut io,
            &true,
            &mut actions,
        )
        .await
        .unwrap();

        assert!(run.is_complete());
        assert!(
            io.output
                .contains("key saved but unverified — it will be tested on your first message.")
        );
    }

    fn available_sandbox_caps() -> cockpit_proto::HostCapabilitySnapshot {
        cockpit_core::daemon::session_worker::sandbox_capability_snapshot(
            cockpit_proto::FeatureCapabilityState::Available,
            cockpit_proto::FeatureCapabilityState::Available,
        )
    }

    async fn run_security_script(
        cwd: &std::path::Path,
        lines: &[&str],
    ) -> (WizardRun, ScriptIo, ProviderSetupActions) {
        run_security_script_with_caps(cwd, lines, available_sandbox_caps()).await
    }

    async fn run_security_script_with_caps(
        cwd: &std::path::Path,
        lines: &[&str],
        caps: cockpit_proto::HostCapabilitySnapshot,
    ) -> (WizardRun, ScriptIo, ProviderSetupActions) {
        let descriptor =
            descriptor_for_cwd_with_caps(crate::wizard::SECURITY_WIZARD_ID, cwd, Some(&caps))
                .expect("security descriptor");
        let mut io = ScriptIo::new(lines);
        let mut actions = ProviderSetupActions::new(cwd.to_path_buf()).with_host_capabilities(caps);
        let run = run_terminal_wizard(descriptor, &mut io, &true, &mut actions)
            .await
            .unwrap();
        (run, io, actions)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn security_wizard_terminal_end_to_end() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _env = CockpitConfigEnvGuard::set_async(&tmp.path().join("config.json")).await;

        let (run, io, _) = run_security_script(tmp.path(), &["", "", "", ""]).await;

        assert!(run.is_complete());
        assert!(
            io.output
                .contains("How should Cockpit confine shell commands")
        );
        assert!(io.output.contains("Workspace trust is per project"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn security_wizard_all_defaults_writes_nothing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config_path = tmp.path().join("config.json");
        std::fs::write(&config_path, "{}\n").expect("write config");
        let _env = CockpitConfigEnvGuard::set_async(&config_path).await;

        let (_, _, actions) = run_security_script(tmp.path(), &["", "", "", ""]).await;

        assert!(actions.security_saved.is_none());
        assert_eq!(
            std::fs::read_to_string(&config_path).expect("read config"),
            "{}\n"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sandbox_step_omits_container_when_unavailable() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _env = CockpitConfigEnvGuard::set_async(&tmp.path().join("config.json")).await;
        let caps = cockpit_core::daemon::session_worker::sandbox_capability_snapshot(
            cockpit_proto::FeatureCapabilityState::Available,
            cockpit_proto::FeatureCapabilityState::Missing,
        );

        let (_, io, actions) = run_security_script_with_caps(
            tmp.path(),
            &["container-readonly", "", "", "", ""],
            caps,
        )
        .await;

        assert!(
            actions.security_saved.is_none(),
            "unavailable container must not persist"
        );
        assert!(
            io.output
                .contains("Choose one of the listed numbers or ids."),
            "terminal wizard must not accept an omitted container row"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sandbox_step_writes_mode() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _env = CockpitConfigEnvGuard::set_async(&tmp.path().join("config.json")).await;

        let (_, _, actions) =
            run_security_script(tmp.path(), &["container-readonly", "", "", ""]).await;

        let path = actions.security_saved.expect("security config saved");
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("read config"))
                .expect("json");
        assert_eq!(raw["sandbox"]["defaultMode"], "container_readonly");
        assert_eq!(raw.as_object().expect("object").len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn redaction_step_validates_numeric() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _env = CockpitConfigEnvGuard::set_async(&tmp.path().join("config.json")).await;

        let (_, io, actions) = run_security_script(tmp.path(), &["", "", "0", "12"]).await;

        assert!(io.output.contains("enter a number from 1 to 4096"));
        let path = actions.security_saved.expect("security config saved");
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("read config"))
                .expect("json");
        assert_eq!(raw["redact"]["min_secret_length"], 12);
    }

    #[test]
    fn security_wizard_copy_mentions_unconfined_and_trust_command() {
        let caps = available_sandbox_caps();
        let descriptor = crate::wizard::security_descriptor_for_config_with_caps(
            &crate::config::extended::ExtendedConfig::default(),
            &caps,
        );
        let sandbox = descriptor
            .steps
            .iter()
            .find(|step| step.id == "sandbox")
            .expect("sandbox step");
        let crate::wizard::StepKind::Select { options } = &sandbox.kind else {
            panic!("sandbox step is select");
        };
        assert!(
            options
                .iter()
                .any(|option| option.id == "off" && option.description.contains("Unconfined"))
        );
        let trust = descriptor
            .steps
            .iter()
            .find(|step| step.id == "workspace-trust")
            .expect("trust step");
        assert!(trust.prompt.contains("cockpit trust set"));
    }
}
