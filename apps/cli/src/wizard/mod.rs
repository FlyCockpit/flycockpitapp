//! Renderer-independent declarative wizard descriptors and transition state.
//!
//! Renderers own terminal/TUI concerns. [`WizardRun`] only validates answers,
//! records navigation, selects branches, and applies descriptor write hooks.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow};

pub const PROVIDER_WIZARD_ID: &str = "provider";
pub const SECURITY_WIZARD_ID: &str = "security";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectOption {
    pub id: &'static str,
    pub label: &'static str,
    pub description: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepKind {
    Select { options: Vec<SelectOption> },
    MultiToggle { options: Vec<SelectOption> },
    Text,
    Secret,
    Info,
    Action { progress: &'static str },
    Confirm,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WizardAnswer {
    Select(String),
    MultiToggle(Vec<String>),
    Text(String),
    Secret(String),
    Confirm(bool),
    Acknowledged,
}

pub type PrefillHook = fn(&WizardRun) -> Option<WizardAnswer>;
pub type ValidationHook = fn(&WizardRun, &WizardAnswer) -> std::result::Result<(), String>;
pub type WriteHook = fn(&WizardRun, &WizardAnswer) -> std::result::Result<(), String>;
pub type BranchHook = fn(&WizardRun, &WizardAnswer) -> Option<&'static str>;

#[derive(Clone)]
pub struct StepDescriptor {
    pub id: &'static str,
    pub prompt: &'static str,
    pub help: &'static str,
    pub kind: StepKind,
    pub default_answer: Option<WizardAnswer>,
    pub prefill: Option<PrefillHook>,
    pub validate: Option<ValidationHook>,
    pub write: Option<WriteHook>,
    pub branch: Option<BranchHook>,
}

impl std::fmt::Debug for StepDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StepDescriptor")
            .field("id", &self.id)
            .field("prompt", &self.prompt)
            .field("help", &self.help)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WritePolicy {
    /// Each write hook is atomic and safe to apply when its step advances.
    PerStep,
    /// Answers remain pending until the final transition succeeds.
    CommitAtEnd,
}

#[derive(Clone, Debug)]
pub struct WizardDescriptor {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub steps: Vec<StepDescriptor>,
    pub write_policy: WritePolicy,
}

#[derive(Clone, Debug)]
pub struct WizardRun {
    descriptor: WizardDescriptor,
    current: Option<usize>,
    history: Vec<usize>,
    answers: BTreeMap<&'static str, WizardAnswer>,
    error: Option<String>,
    aborted: bool,
    writes_applied: bool,
}

impl WizardRun {
    pub fn new(descriptor: WizardDescriptor) -> Result<Self> {
        if descriptor.steps.is_empty() {
            return Err(anyhow!("wizard `{}` has no steps", descriptor.id));
        }
        let mut ids = std::collections::BTreeSet::new();
        for step in &descriptor.steps {
            if !ids.insert(step.id) {
                return Err(anyhow!(
                    "wizard `{}` contains duplicate step `{}`",
                    descriptor.id,
                    step.id
                ));
            }
        }
        Ok(Self {
            descriptor,
            current: Some(0),
            history: Vec::new(),
            answers: BTreeMap::new(),
            error: None,
            aborted: false,
            writes_applied: false,
        })
    }

    pub fn descriptor(&self) -> &WizardDescriptor {
        &self.descriptor
    }

    pub fn current_step(&self) -> Option<&StepDescriptor> {
        self.current.map(|index| &self.descriptor.steps[index])
    }

    pub fn current_step_id(&self) -> Option<&'static str> {
        self.current_step().map(|step| step.id)
    }

    pub fn answer(&self, step_id: &str) -> Option<&WizardAnswer> {
        self.answers.get(step_id)
    }

    pub fn answers(&self) -> &BTreeMap<&'static str, WizardAnswer> {
        &self.answers
    }

    pub fn prefill(&self) -> Option<WizardAnswer> {
        let step = self.current_step()?;
        self.answer(step.id)
            .cloned()
            .or_else(|| step.default_answer.clone())
            .or_else(|| step.prefill.and_then(|prefill| prefill(self)))
    }

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub fn is_complete(&self) -> bool {
        self.current.is_none() && !self.aborted
    }

    pub fn is_aborted(&self) -> bool {
        self.aborted
    }

    pub fn submit(&mut self, answer: WizardAnswer) -> std::result::Result<(), String> {
        let Some(current) = self.current else {
            return Err("wizard is not awaiting an answer".to_string());
        };
        if self.aborted {
            return Err("wizard was aborted".to_string());
        }
        let step = &self.descriptor.steps[current];
        if let Some(validate) = step.validate
            && let Err(error) = validate(self, &answer)
        {
            self.error = Some(error.clone());
            return Err(error);
        }

        self.error = None;
        self.answers.insert(step.id, answer.clone());
        if self.descriptor.write_policy == WritePolicy::PerStep
            && let Some(write) = step.write
            && let Err(error) = write(self, &answer)
        {
            self.error = Some(error.clone());
            return Err(error);
        }

        let next = step
            .branch
            .and_then(|branch| branch(self, &answer))
            .map(|id| {
                self.descriptor
                    .steps
                    .iter()
                    .position(|candidate| candidate.id == id)
                    .ok_or_else(|| format!("wizard branch targets unknown step `{id}`"))
            })
            .transpose()?
            .or_else(|| (current + 1 < self.descriptor.steps.len()).then_some(current + 1));

        match next {
            Some(next) => {
                self.history.push(current);
                self.current = Some(next);
                Ok(())
            }
            None => self.finish(),
        }
    }

    fn finish(&mut self) -> std::result::Result<(), String> {
        if self.descriptor.write_policy == WritePolicy::CommitAtEnd && !self.writes_applied {
            for step in &self.descriptor.steps {
                let Some(answer) = self.answers.get(step.id) else {
                    continue;
                };
                if let Some(write) = step.write
                    && let Err(error) = write(self, answer)
                {
                    self.error = Some(error.clone());
                    return Err(error);
                }
            }
            self.writes_applied = true;
        }
        self.current = None;
        Ok(())
    }

    pub fn back(&mut self) -> bool {
        let Some(previous) = self.history.pop() else {
            return false;
        };
        self.current = Some(previous);
        self.error = None;
        true
    }

    pub fn abort(&mut self) {
        if self.descriptor.write_policy == WritePolicy::CommitAtEnd && !self.writes_applied {
            self.answers.clear();
        }
        self.current = None;
        self.error = None;
        self.aborted = true;
    }

    /// Restore a descriptor step while retaining prior answers. This is used
    /// only when an external action (such as an OAuth component) asks the
    /// renderer to return to its owning input step.
    pub fn return_to(&mut self, step_id: &str) -> std::result::Result<(), String> {
        let index = self
            .descriptor
            .steps
            .iter()
            .position(|step| step.id == step_id)
            .ok_or_else(|| format!("unknown wizard step `{step_id}`"))?;
        self.current = Some(index);
        self.error = None;
        Ok(())
    }
}

pub fn registry() -> Vec<WizardDescriptor> {
    vec![provider_descriptor(), security_descriptor()]
}

pub fn descriptor(id: &str) -> Option<WizardDescriptor> {
    registry().into_iter().find(|wizard| wizard.id == id)
}

pub fn provider_descriptor() -> WizardDescriptor {
    use crate::providers::TEMPLATES;

    let template_options = TEMPLATES
        .iter()
        .map(|template| SelectOption {
            id: template.id,
            label: template.display,
            description: template.hint.unwrap_or("Provider template"),
        })
        .collect();
    WizardDescriptor {
        id: PROVIDER_WIZARD_ID,
        title: "Add provider",
        description: "Configure an inference provider and its authentication",
        write_policy: WritePolicy::PerStep,
        steps: vec![
            StepDescriptor {
                id: "template",
                prompt: "Choose a provider template",
                help: "The template pre-fills the provider id, URL, and authentication shape.",
                kind: StepKind::Select {
                    options: template_options,
                },
                default_answer: None,
                prefill: None,
                validate: Some(validate_select),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "id",
                prompt: "Provider id",
                help: "Use lowercase letters, digits, `-`, or `_`.",
                kind: StepKind::Text,
                default_answer: None,
                prefill: Some(provider_id_prefill),
                validate: Some(validate_provider_id),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "url",
                prompt: "Base URL",
                help: "The endpoint must start with http:// or https://.",
                kind: StepKind::Text,
                default_answer: None,
                prefill: Some(provider_url_prefill),
                validate: Some(validate_provider_url),
                write: None,
                branch: Some(provider_auth_branch),
            },
            action_step(
                "headers",
                "Configure HTTP headers",
                "Editing provider headers…",
            ),
            action_step(
                "copilot-auth",
                "Configure GitHub authentication",
                "Configuring GitHub authentication…",
            ),
            action_step(
                "grok-oauth",
                "Sign in to Grok",
                "Waiting for browser authorization…",
            ),
            action_step(
                "codex-oauth",
                "Sign in to Codex",
                "Waiting for device authorization…",
            ),
            StepDescriptor {
                id: "saving",
                prompt: "Save provider",
                help: "The provider is written atomically at this step.",
                kind: StepKind::Action {
                    progress: "Saving provider…",
                },
                default_answer: None,
                prefill: None,
                validate: None,
                write: None,
                branch: Some(provider_fetch_branch),
            },
            action_step("fetching", "Fetch models", "Fetching /models…"),
            StepDescriptor {
                id: "done",
                prompt: "Provider setup complete",
                help: "Continue to return to the provider list.",
                kind: StepKind::Info,
                default_answer: None,
                prefill: None,
                validate: None,
                write: None,
                branch: None,
            },
        ],
    }
}

pub fn security_descriptor() -> WizardDescriptor {
    security_descriptor_for_config(&crate::config::extended::ExtendedConfig::default())
}

pub fn security_descriptor_for_config(
    current: &crate::config::extended::ExtendedConfig,
) -> WizardDescriptor {
    WizardDescriptor {
        id: SECURITY_WIZARD_ID,
        title: "Security posture",
        description: "Review sandboxing, approvals, trusted-only, redaction, and workspace trust",
        write_policy: WritePolicy::CommitAtEnd,
        steps: vec![
            StepDescriptor {
                id: "sandbox",
                prompt: "How should Cockpit confine shell commands by default?",
                help: "Keep the host shell sandbox unless you specifically need container isolation or unconfined commands. `off` means commands the model runs are unconfined.",
                kind: StepKind::Select {
                    options: vec![
                        SelectOption {
                            id: sandbox_mode_id(current.sandbox.default_mode),
                            label: "Keep current sandbox setting",
                            description: "Recommended default is sandbox. Commands run inside the OS shell sandbox when available.",
                        },
                        SelectOption {
                            id: "container",
                            label: "container",
                            description: "Run commands in a Docker/Podman container. Shown even if docker/podman is not found.",
                        },
                        SelectOption {
                            id: "container-readonly",
                            label: "container-readonly",
                            description: "Run in a container with the project mounted read-only.",
                        },
                        SelectOption {
                            id: "off",
                            label: "off",
                            description: "Unconfined: commands the model runs are not sandboxed.",
                        },
                    ],
                },
                default_answer: Some(WizardAnswer::Select(
                    sandbox_mode_id(current.sandbox.default_mode).to_string(),
                )),
                prefill: None,
                validate: Some(validate_sandbox_mode),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "approval",
                prompt: "How should gated commands and network calls be approved?",
                help: "Manual asks every time. Auto uses the utility-model safety gate for safe calls and asks on unsafe or unavailable. Yolo runs gated calls unprompted. Remembered command/path grants can be once, session, project, or global; project/global grants are machine-local.",
                kind: StepKind::Select {
                    options: vec![
                        SelectOption {
                            id: current.default_approval_mode.as_str(),
                            label: "Keep current approval mode",
                            description: "Recommended default is manual. You approve every gated command, web fetch, and MCP call.",
                        },
                        SelectOption {
                            id: "auto",
                            label: "auto",
                            description: "Use the utility-model safety gate for safe calls; ask when unsafe or unavailable.",
                        },
                        SelectOption {
                            id: "yolo",
                            label: "yolo",
                            description: "Runs gated commands and network calls unprompted.",
                        },
                    ],
                },
                default_answer: Some(WizardAnswer::Select(
                    current.default_approval_mode.as_str().to_string(),
                )),
                prefill: None,
                validate: Some(validate_approval_mode),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "trusted-only",
                prompt: "Require trusted providers/models only?",
                help: "Trusted-only blocks untrusted provider/model choices. Trusted providers can receive original text; untrusted providers receive redacted text.",
                kind: StepKind::Confirm,
                default_answer: Some(WizardAnswer::Confirm(current.trusted_only)),
                prefill: None,
                validate: None,
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "redaction",
                prompt: "Minimum secret length for redaction",
                help: "For untrusted models, Cockpit redacts known secrets from your environment and Cockpit's secret store. Keep 8 unless short secrets are common in your workflow.",
                kind: StepKind::Text,
                default_answer: Some(WizardAnswer::Text(
                    current.redact.min_secret_length.to_string(),
                )),
                prefill: None,
                validate: Some(validate_min_secret_length),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "workspace-trust",
                prompt: "Workspace trust is per project. Use `cockpit trust set <path> --mode trust|ignore-config|untrusted` to change it.",
                help: "Trust allows project config. Ignore-config opens the workspace without project config. Untrusted blocks the workspace.",
                kind: StepKind::Info,
                default_answer: None,
                prefill: None,
                validate: None,
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "security-save",
                prompt: "Apply security settings",
                help: "Only values that differ from the starting effective configuration are written.",
                kind: StepKind::Action {
                    progress: "Applying security settings…",
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

pub(crate) fn sandbox_mode_id(mode: crate::tools::sandbox_mode::SandboxMode) -> &'static str {
    match mode {
        crate::tools::sandbox_mode::SandboxMode::Off => "off",
        crate::tools::sandbox_mode::SandboxMode::Sandbox => "sandbox",
        crate::tools::sandbox_mode::SandboxMode::Container => "container",
        crate::tools::sandbox_mode::SandboxMode::ContainerReadonly => "container-readonly",
    }
}

pub(crate) fn sandbox_mode_from_id(id: &str) -> Option<crate::tools::sandbox_mode::SandboxMode> {
    Some(match id {
        "off" => crate::tools::sandbox_mode::SandboxMode::Off,
        "sandbox" | "on" => crate::tools::sandbox_mode::SandboxMode::Sandbox,
        "container" => crate::tools::sandbox_mode::SandboxMode::Container,
        "container-readonly" | "container_readonly" => {
            crate::tools::sandbox_mode::SandboxMode::ContainerReadonly
        }
        _ => return None,
    })
}

pub(crate) fn approval_mode_from_id(id: &str) -> Option<crate::config::extended::ApprovalMode> {
    Some(match id {
        "manual" => crate::config::extended::ApprovalMode::Manual,
        "auto" => crate::config::extended::ApprovalMode::Auto,
        "yolo" => crate::config::extended::ApprovalMode::Yolo,
        _ => return None,
    })
}

pub(crate) fn trusted_only_answer(run: &WizardRun) -> Option<bool> {
    let WizardAnswer::Confirm(value) = run.answer("trusted-only")? else {
        return None;
    };
    Some(*value)
}

pub(crate) fn min_secret_length_answer(run: &WizardRun) -> Option<usize> {
    let WizardAnswer::Text(value) = run.answer("redaction")? else {
        return None;
    };
    value.trim().parse().ok()
}

pub(crate) fn sandbox_mode_answer(
    run: &WizardRun,
) -> Option<crate::tools::sandbox_mode::SandboxMode> {
    let WizardAnswer::Select(value) = run.answer("sandbox")? else {
        return None;
    };
    sandbox_mode_from_id(value)
}

pub(crate) fn approval_mode_answer(
    run: &WizardRun,
) -> Option<crate::config::extended::ApprovalMode> {
    let WizardAnswer::Select(value) = run.answer("approval")? else {
        return None;
    };
    approval_mode_from_id(value)
}

fn action_step(id: &'static str, prompt: &'static str, progress: &'static str) -> StepDescriptor {
    StepDescriptor {
        id,
        prompt,
        help: progress,
        kind: StepKind::Action { progress },
        default_answer: None,
        prefill: None,
        validate: None,
        write: None,
        branch: Some(if id == "fetching" {
            fetching_to_done
        } else {
            action_to_saving
        }),
    }
}

fn validate_select(_: &WizardRun, answer: &WizardAnswer) -> std::result::Result<(), String> {
    match answer {
        WizardAnswer::Select(value) if !value.is_empty() => Ok(()),
        _ => Err("choose one option".to_string()),
    }
}

fn validate_sandbox_mode(_: &WizardRun, answer: &WizardAnswer) -> std::result::Result<(), String> {
    match answer {
        WizardAnswer::Select(value) if sandbox_mode_from_id(value).is_some() => Ok(()),
        _ => Err("choose sandbox, container, container-readonly, or off".to_string()),
    }
}

fn validate_approval_mode(_: &WizardRun, answer: &WizardAnswer) -> std::result::Result<(), String> {
    match answer {
        WizardAnswer::Select(value) if approval_mode_from_id(value).is_some() => Ok(()),
        _ => Err("choose manual, auto, or yolo".to_string()),
    }
}

fn validate_min_secret_length(
    _: &WizardRun,
    answer: &WizardAnswer,
) -> std::result::Result<(), String> {
    let WizardAnswer::Text(value) = answer else {
        return Err("enter a number".to_string());
    };
    let parsed = value
        .trim()
        .parse::<usize>()
        .map_err(|_| "enter a number from 1 to 4096".to_string())?;
    if (1..=4096).contains(&parsed) {
        Ok(())
    } else {
        Err("enter a number from 1 to 4096".to_string())
    }
}

fn validate_provider_id(_: &WizardRun, answer: &WizardAnswer) -> std::result::Result<(), String> {
    let WizardAnswer::Text(id) = answer else {
        return Err("provider id must be text".to_string());
    };
    if id.is_empty() {
        return Err("id cannot be empty".to_string());
    }
    if id.chars().all(|character| {
        character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '-' | '_')
    }) {
        Ok(())
    } else {
        Err("id must be lowercase letters, digits, `-`, or `_`".to_string())
    }
}

fn validate_provider_url(_: &WizardRun, answer: &WizardAnswer) -> std::result::Result<(), String> {
    match answer {
        WizardAnswer::Text(url) if url.starts_with("http://") || url.starts_with("https://") => {
            Ok(())
        }
        _ => Err("url must start with http:// or https://".to_string()),
    }
}

pub(crate) fn selected_provider_template(
    run: &WizardRun,
) -> Option<&'static crate::providers::ProviderTemplate> {
    let WizardAnswer::Select(id) = run.answer("template")? else {
        return None;
    };
    crate::providers::template_by_id(id)
}

pub(crate) fn provider_id_answer(run: &WizardRun) -> Option<String> {
    let WizardAnswer::Text(id) = run.answer("id")? else {
        return None;
    };
    Some(id.trim().to_string())
}

pub(crate) fn provider_url_answer(run: &WizardRun) -> Option<String> {
    let WizardAnswer::Text(url) = run.answer("url")? else {
        return None;
    };
    Some(url.trim_end_matches('/').to_string())
}

pub(crate) fn provider_entry_from_answers(
    run: &WizardRun,
    headers: Vec<crate::config::providers::HeaderSpec>,
) -> Option<crate::config::providers::ProviderEntry> {
    let template = selected_provider_template(run)?;
    provider_entry_for_template(template, provider_url_answer(run)?, headers).into()
}

pub(crate) fn provider_entry_for_template(
    template: &'static crate::providers::ProviderTemplate,
    url: String,
    headers: Vec<crate::config::providers::HeaderSpec>,
) -> crate::config::providers::ProviderEntry {
    use crate::auth::{codex_oauth, xai_oauth};
    use crate::config::providers::{AuthKind, ProviderEntry, ProviderModelCatalog};

    let auth =
        if template.id == xai_oauth::CREDENTIAL_KEY || template.id == codex_oauth::CREDENTIAL_KEY {
            Some(AuthKind::OAuth)
        } else {
            Some(template.auth)
        };
    let credential_ref = if template.id == xai_oauth::CREDENTIAL_KEY {
        Some(xai_oauth::CREDENTIAL_KEY.to_string())
    } else if template.id == codex_oauth::CREDENTIAL_KEY {
        Some(codex_oauth::CREDENTIAL_KEY.to_string())
    } else {
        None
    };
    ProviderEntry {
        name: Some(template.display.to_string()),
        template: Some(template.id.to_string()),
        url,
        headers,
        models_fetched_at: None,
        model_catalog: ProviderModelCatalog::Live,
        favorite: None,
        allow_insecure_http: false,
        credential_ref,
        auth,
        trust: None,
        location: None,
        quality_rank: None,
        cost_rank: None,
        subagent_invokable: None,
        embeddings: None,
        availability: Default::default(),
        cache: Default::default(),
        shrink: Default::default(),
        context: Default::default(),
        auto_prune: None,
        timeout: Default::default(),
        wire_api: template.default_wire_api,
        backup: None,
        mode: None,
        inline_think: None,
        hint_tool_call_corrections: None,
        text_embedded_recovery: None,
        thinking_params: Default::default(),
        models: vec![],
        capabilities: Default::default(),
        provider_metadata: Default::default(),
        last_model_fetch: None,
    }
}

fn provider_id_prefill(run: &WizardRun) -> Option<WizardAnswer> {
    let template = selected_provider_template(run)?;
    Some(WizardAnswer::Text(
        if template.use_id_as_default {
            template.id
        } else {
            ""
        }
        .to_string(),
    ))
}

fn provider_url_prefill(run: &WizardRun) -> Option<WizardAnswer> {
    Some(WizardAnswer::Text(
        selected_provider_template(run)?.url.to_string(),
    ))
}

fn provider_auth_branch(run: &WizardRun, _: &WizardAnswer) -> Option<&'static str> {
    Some(match selected_provider_template(run)?.id {
        "copilot" => "copilot-auth",
        "grok-oauth" => "grok-oauth",
        "codex-oauth" => "codex-oauth",
        _ => "headers",
    })
}

fn action_to_saving(_: &WizardRun, _: &WizardAnswer) -> Option<&'static str> {
    Some("saving")
}

fn fetching_to_done(_: &WizardRun, _: &WizardAnswer) -> Option<&'static str> {
    Some("done")
}

fn provider_fetch_branch(run: &WizardRun, _: &WizardAnswer) -> Option<&'static str> {
    Some(
        if selected_provider_template(run)?.supports_models_endpoint {
            "fetching"
        } else {
            "done"
        },
    )
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    static WRITE_COUNT: AtomicUsize = AtomicUsize::new(0);
    static WRITE_COUNT_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn write_count_test_lock() -> std::sync::MutexGuard<'static, ()> {
        WRITE_COUNT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn count_write(_: &WizardRun, _: &WizardAnswer) -> std::result::Result<(), String> {
        WRITE_COUNT.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn reject_bad(_: &WizardRun, answer: &WizardAnswer) -> std::result::Result<(), String> {
        match answer {
            WizardAnswer::Text(value) if value == "good" => Ok(()),
            _ => Err("try again".to_string()),
        }
    }

    fn branch_on_choice(_: &WizardRun, answer: &WizardAnswer) -> Option<&'static str> {
        match answer {
            WizardAnswer::Select(value) if value == "fast" => Some("finish"),
            _ => Some("slow"),
        }
    }

    fn test_descriptor(policy: WritePolicy) -> WizardDescriptor {
        WizardDescriptor {
            id: "test",
            title: "Test",
            description: "Test wizard",
            write_policy: policy,
            steps: vec![
                StepDescriptor {
                    id: "start",
                    prompt: "start",
                    help: "",
                    kind: StepKind::Select { options: vec![] },
                    default_answer: None,
                    prefill: None,
                    validate: None,
                    write: Some(count_write),
                    branch: Some(branch_on_choice),
                },
                StepDescriptor {
                    id: "slow",
                    prompt: "slow",
                    help: "",
                    kind: StepKind::Text,
                    default_answer: None,
                    prefill: None,
                    validate: Some(reject_bad),
                    write: Some(count_write),
                    branch: None,
                },
                StepDescriptor {
                    id: "finish",
                    prompt: "finish",
                    help: "",
                    kind: StepKind::Info,
                    default_answer: None,
                    prefill: None,
                    validate: None,
                    write: Some(count_write),
                    branch: None,
                },
            ],
        }
    }

    #[test]
    fn select_branching_picks_next_step() {
        let _lock = write_count_test_lock();
        let mut run = WizardRun::new(test_descriptor(WritePolicy::PerStep)).unwrap();
        run.submit(WizardAnswer::Select("fast".to_string()))
            .unwrap();
        assert_eq!(run.current_step_id(), Some("finish"));
    }

    #[test]
    fn validation_failure_reprompts() {
        let _lock = write_count_test_lock();
        let mut run = WizardRun::new(test_descriptor(WritePolicy::PerStep)).unwrap();
        run.submit(WizardAnswer::Select("slow".to_string()))
            .unwrap();
        assert_eq!(
            run.submit(WizardAnswer::Text("bad".to_string())),
            Err("try again".to_string())
        );
        assert_eq!(run.current_step_id(), Some("slow"));
        assert_eq!(run.error(), Some("try again"));
    }

    #[test]
    fn commit_at_end_applies_writes_once() {
        let _lock = write_count_test_lock();
        WRITE_COUNT.store(0, Ordering::SeqCst);
        let mut run = WizardRun::new(test_descriptor(WritePolicy::CommitAtEnd)).unwrap();
        run.submit(WizardAnswer::Select("fast".to_string()))
            .unwrap();
        assert_eq!(WRITE_COUNT.load(Ordering::SeqCst), 0);
        run.submit(WizardAnswer::Acknowledged).unwrap();
        assert_eq!(WRITE_COUNT.load(Ordering::SeqCst), 2);
        assert!(run.is_complete());
    }

    #[test]
    fn abort_discards_pending_writes() {
        let _lock = write_count_test_lock();
        WRITE_COUNT.store(0, Ordering::SeqCst);
        let mut run = WizardRun::new(test_descriptor(WritePolicy::CommitAtEnd)).unwrap();
        run.submit(WizardAnswer::Select("slow".to_string()))
            .unwrap();
        run.abort();
        assert!(run.answers().is_empty());
        assert_eq!(WRITE_COUNT.load(Ordering::SeqCst), 0);
    }
}
