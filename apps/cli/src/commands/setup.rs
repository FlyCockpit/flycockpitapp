use std::future::Future;
use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;

use crate::cli::SetupArgs;
use crate::config::dirs::{CONFIG_FILE, most_specific_config_write_target};
use crate::config::providers::{ConfigDoc, HeaderSpec, ModelMergePolicy, OnUnlistedModelsFetch};
use crate::providers::models_fetch::{self, FetchOutcome};
use crate::wizard::{
    StepKind, WizardAnswer, WizardDescriptor, WizardRun, provider_entry_from_answers,
    provider_id_answer, selected_provider_template,
};

pub async fn run(args: SetupArgs) -> Result<()> {
    let stdin_tty = io::stdin().is_terminal();
    let cwd = std::env::current_dir().context("getting cwd")?;
    let mut io = StdTerminalIo;
    let wizard = match args.wizard.as_deref() {
        Some(id) => crate::wizard::descriptor(id)
            .ok_or_else(|| anyhow!("unknown setup wizard `{id}`; run `cockpit setup` to list"))?,
        None => choose_wizard(&mut io, stdin_tty).await?,
    };
    let mut actions = ProviderSetupActions::new(cwd);
    run_terminal_wizard(wizard, &mut io, &stdin_tty, &mut actions).await?;
    Ok(())
}

async fn choose_wizard(io: &mut dyn TerminalIo, tty: bool) -> Result<WizardDescriptor> {
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
        if let Some(wizard) = resolve_wizard_choice(&input) {
            return Ok(wizard);
        }
        io.write_line("Choose one of the listed wizard numbers or ids.")?;
    }
}

fn resolve_wizard_choice(input: &str) -> Option<WizardDescriptor> {
    if let Ok(number) = input.parse::<usize>() {
        return crate::wizard::registry()
            .into_iter()
            .nth(number.checked_sub(1)?);
    }
    crate::wizard::descriptor(input)
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

type ActionFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + 'a>>;

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
            StepKind::Select { options } => {
                write_select(io, &run, step.prompt, options)?;
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
                    if let Some(answer) = select_answer(options, input.trim()) {
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
                io.write(&format!("{} [y/N]: ", step.prompt))?;
                let input = read_input(io)?;
                if go_back(&mut run, &input, io)? {
                    continue;
                }
                submit(
                    &mut run,
                    WizardAnswer::Confirm(matches!(input.trim(), "y" | "Y" | "yes" | "YES")),
                    io,
                )?;
            }
            StepKind::MultiToggle { options } => {
                io.write_line(step.prompt)?;
                for option in options {
                    io.write_line(&format!("  - {} ({})", option.label, option.id))?;
                }
                io.write("Comma-separated ids: ")?;
                let input = read_input(io)?;
                if go_back(&mut run, &input, io)? {
                    continue;
                }
                let values = input
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
                    .collect();
                submit(&mut run, WizardAnswer::MultiToggle(values), io)?;
            }
        }
    }
    Ok(run)
}

fn write_select(
    io: &mut dyn TerminalIo,
    run: &WizardRun,
    prompt: &str,
    options: &[crate::wizard::SelectOption],
) -> io::Result<()> {
    io.write_line(prompt)?;
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

struct ProviderSetupActions {
    cwd: PathBuf,
    headers: Vec<HeaderSpec>,
    saved: Option<(String, PathBuf)>,
}

impl ProviderSetupActions {
    fn new(cwd: PathBuf) -> Self {
        Self {
            cwd,
            headers: Vec::new(),
            saved: None,
        }
    }

    fn config_path(&self) -> PathBuf {
        most_specific_config_write_target(&self.cwd)
            .unwrap_or_else(|| self.cwd.join(".cockpit").join(CONFIG_FILE))
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
                io.write_line("Starting Grok OAuth login.")?;
                let login = crate::auth::xai_oauth::begin_manual_login().await?;
                io.write_line("Open this URL and approve access:")?;
                io.write_line(&login.authorize_url)?;
                if !crate::clipboard::is_ssh() {
                    let _ = crate::browser::open(&login.authorize_url);
                }
                io.write("Paste the callback URL or code: ")?;
                let input = io.read_line().context("reading Grok OAuth callback")?;
                crate::auth::xai_oauth::complete_manual_login(login, input.trim()).await?;
                io.write_line("Grok OAuth login complete.")?;
            }
            "codex-oauth" => {
                io.write_line("Starting Codex device-code login.")?;
                let login = crate::auth::codex_oauth::begin_device_code_login().await?;
                io.write_line(&login.verification_uri)?;
                io.write_line(&format!("Enter code: {}", login.user_code))?;
                if !crate::clipboard::is_ssh() {
                    let _ = crate::browser::open(&login.verification_uri);
                }
                crate::auth::codex_oauth::complete_device_code_login(login).await?;
                io.write_line("Codex OAuth login complete.")?;
            }
            "saving" => {
                self.save_provider(run, io)?;
            }
            "fetching" => {
                self.fetch_models(run, io).await?;
            }
            _ => {}
        }
        Ok(())
    }

    fn save_provider(&mut self, run: &WizardRun, io: &mut dyn TerminalIo) -> Result<()> {
        let id = provider_id_answer(run).context("provider id answer")?;
        let mut entry =
            provider_entry_from_answers(run, self.headers.clone()).context("provider answers")?;
        let config_path = self.config_path();
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut doc = ConfigDoc::load(&config_path)?;
        let mut cfg = doc.providers();
        if cfg.providers.contains_key(&id) {
            bail!("a provider with id `{id}` already exists");
        }
        let mut providers = std::collections::BTreeMap::from([(id.clone(), entry.clone())]);
        let notice = crate::secret_ref::protect_literal_headers(&mut providers, None)?;
        entry = providers
            .remove(&id)
            .expect("provider inserted for secret protection");
        cfg.providers.insert(id.clone(), entry);
        doc.write(&cfg)?;
        self.saved = Some((id.clone(), config_path));
        if let Some(notice) = notice {
            io.write_line(&format!("Saved provider `{id}`. {}", notice.render()))?;
        } else {
            io.write_line(&format!("Saved provider `{id}`."))?;
        }
        Ok(())
    }

    async fn fetch_models(&mut self, run: &WizardRun, io: &mut dyn TerminalIo) -> Result<()> {
        let Some((id, config_path)) = self.saved.clone() else {
            return Ok(());
        };
        let Some(template) = selected_provider_template(run) else {
            return Ok(());
        };
        if !template.supports_models_endpoint {
            io.write_line("Provider has no /models endpoint.")?;
            return Ok(());
        }
        let mut doc = ConfigDoc::load(&config_path)?;
        let mut cfg = doc.providers();
        let Some(entry) = cfg.providers.get(&id).cloned() else {
            return Ok(());
        };
        let resolved = match models_fetch::resolve_provider_request_async(&id, &entry).await {
            Ok(resolved) => resolved,
            Err(error) => {
                io.write_line(&format!("Skipped model fetch: {error}"))?;
                return Ok(());
            }
        };
        let outcome = models_fetch::fetch_models_for_provider(
            &id,
            &entry,
            &resolved,
            Duration::from_secs(15),
        )
        .await;
        let Some(entry) = cfg.providers.get_mut(&id) else {
            return Ok(());
        };
        match outcome {
            Ok(FetchOutcome::Models { models, catalog }) => {
                let policy = match cfg
                    .on_unlisted_models_fetch
                    .unwrap_or(OnUnlistedModelsFetch::Keep)
                {
                    OnUnlistedModelsFetch::Remove => ModelMergePolicy::RemoveUnlisted,
                    OnUnlistedModelsFetch::Ask | OnUnlistedModelsFetch::Keep => {
                        ModelMergePolicy::KeepUnlisted
                    }
                };
                let before = entry.models.clone();
                entry.models = crate::config::providers::merge_fetched_models_with_policy(
                    entry.effective_template(&id),
                    &before,
                    models,
                    policy,
                );
                entry.models_fetched_at = Some(Utc::now());
                entry.model_catalog = catalog;
                entry.mark_model_fetch_success(catalog);
                io.write_line(&format!("Fetched {} model(s).", entry.models.len()))?;
            }
            Ok(FetchOutcome::FallbackAvailable { reason, .. }) => {
                let reason = crate::config::providers::redact_model_fetch_reason(reason);
                entry.mark_model_fetch_failed_kept_existing(reason.clone());
                io.write_line(&format!("Model fetch fallback available: {reason}"))?;
            }
            Ok(FetchOutcome::Unsupported) => {
                entry.mark_model_fetch_unsupported();
                io.write_line("Provider has no /models endpoint.")?;
            }
            Err(error) => {
                let reason = crate::config::providers::redact_model_fetch_reason(error.to_string());
                entry.mark_model_fetch_failed_kept_existing(reason.clone());
                io.write_line(&format!("Model fetch failed: {reason}"))?;
            }
        }
        doc.write(&cfg)?;
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    async fn terminal_renderer_runs_provider_wizard() {
        let mut io = ScriptIo::new(&["openai", "", ""]);
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
        assert_eq!(actions.fetches, 1);
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
        let mut io = ScriptIo::new(&["openai", "back", "openai", "", ""]);
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
}
