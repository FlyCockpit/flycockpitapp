//! Renderer-independent declarative wizard descriptors and transition state.
//!
//! Renderers own terminal/TUI concerns. [`WizardRun`] only validates answers,
//! records navigation, selects branches, and applies descriptor write hooks.

use std::borrow::Cow;
use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow};

mod apply;

pub use apply::{
    ModelAnswersOutcome, apply_model_answers, apply_security_answers,
    apply_security_answers_with_caps, apply_setup_wizard_answers,
    apply_setup_wizard_answers_authoritative, compose_wizard_host_capabilities, descriptor_for_cwd,
    descriptor_for_cwd_with_caps, model_descriptor_for_cwd, security_config_path,
};

pub const PROVIDER_WIZARD_ID: &str = "provider";
pub const SECURITY_WIZARD_ID: &str = "security";
pub const MODEL_WIZARD_ID: &str = "model";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectOption {
    pub id: Cow<'static, str>,
    pub label: Cow<'static, str>,
    pub description: Cow<'static, str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepKind {
    Select { options: Vec<SelectOption> },
    MultiToggle { options: Vec<SelectOption> },
    ToolSurface,
    Text,
    Secret,
    Info,
    Action { progress: &'static str },
    Confirm,
}

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum WizardAnswer {
    Select(String),
    MultiToggle(Vec<String>),
    ToolSurface(crate::agents::ToolSurfaceSelection),
    Text(String),
    Secret(String),
    Confirm(bool),
    Acknowledged,
}

impl std::fmt::Debug for WizardAnswer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Select(value) => formatter.debug_tuple("Select").field(value).finish(),
            Self::MultiToggle(values) => {
                formatter.debug_tuple("MultiToggle").field(values).finish()
            }
            Self::ToolSurface(value) => formatter.debug_tuple("ToolSurface").field(value).finish(),
            Self::Text(value) => formatter.debug_tuple("Text").field(value).finish(),
            Self::Secret(_) => formatter.write_str("Secret([REDACTED])"),
            Self::Confirm(value) => formatter.debug_tuple("Confirm").field(value).finish(),
            Self::Acknowledged => formatter.write_str("Acknowledged"),
        }
    }
}

pub type PrefillHook = fn(&WizardRun) -> Option<WizardAnswer>;
pub type ValidationHook = fn(&WizardRun, &WizardAnswer) -> std::result::Result<(), String>;
pub type WriteHook = fn(&WizardRun, &WizardAnswer) -> std::result::Result<(), String>;
pub type BranchHook = fn(&WizardRun, &WizardAnswer) -> Option<&'static str>;
pub type HelpHook = fn(&WizardRun) -> Option<String>;

#[derive(Clone)]
pub struct StepDescriptor {
    pub id: &'static str,
    pub prompt: &'static str,
    pub help: &'static str,
    pub help_hook: Option<HelpHook>,
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
    pub(crate) model_context: Option<ModelWizardContext>,
}

#[derive(Clone, Debug)]
pub(crate) struct ModelWizardContext {
    default_provider: Option<String>,
    default_model_ref: Option<String>,
    provider_trust_defaults: BTreeMap<String, crate::config::providers::ModelTrust>,
    models: BTreeMap<String, ModelWizardPrefill>,
}

#[derive(Clone, Debug)]
struct ModelWizardPrefill {
    trust: crate::config::providers::ModelTrust,
    capabilities: Vec<String>,
    context_tokens: Option<u32>,
    max_output_tokens: Option<u32>,
    thinking: Option<crate::config::providers::ThinkingMode>,
    subagent_invokable: bool,
    can_delegate: bool,
    make_default: bool,
    system_prompt: Option<String>,
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

impl Drop for WizardRun {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        for answer in self.answers.values_mut() {
            if let WizardAnswer::Secret(value) = answer {
                value.zeroize();
            }
        }
    }
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

    pub fn current_provider_step(&self) -> Option<ProviderWizardStep> {
        (self.descriptor.id == PROVIDER_WIZARD_ID).then(|| {
            ProviderWizardStep::from_source_id(
                self.current_step_id()
                    .expect("a live provider wizard has a current step"),
            )
        })
    }

    pub fn answer(&self, step_id: &str) -> Option<&WizardAnswer> {
        self.answers.get(step_id)
    }

    pub fn answers(&self) -> &BTreeMap<&'static str, WizardAnswer> {
        &self.answers
    }

    /// Encode the completed answers for the daemon-owned setup mutation RPC.
    /// Descriptors and hooks never cross the wire.
    pub fn answers_json(&self) -> Result<String> {
        let answers = self
            .answers
            .iter()
            .map(|(id, answer)| ((*id).to_string(), answer))
            .collect::<BTreeMap<_, _>>();
        serde_json::to_string(&answers).context("serializing wizard answers")
    }

    /// Rebuild a validated run from daemon RPC answers. The descriptor is
    /// selected from the daemon's current config, so client-side stale steps
    /// cannot bypass current validation or branching.
    pub fn from_answers_json(descriptor: WizardDescriptor, json: &str) -> Result<Self> {
        let answers: BTreeMap<String, WizardAnswer> =
            serde_json::from_str(json).context("deserializing wizard answers")?;
        let mut run = Self::new(descriptor)?;
        while let Some(step) = run.current_step() {
            let answer = answers
                .get(step.id)
                .cloned()
                .ok_or_else(|| anyhow!("missing answer for wizard step `{}`", step.id))?;
            run.submit(answer)
                .map_err(|error| anyhow!("invalid wizard answer: {error}"))?;
        }
        Ok(run)
    }

    pub fn prefill(&self) -> Option<WizardAnswer> {
        let step = self.current_step()?;
        self.answer(step.id)
            .cloned()
            .or_else(|| step.prefill.and_then(|prefill| prefill(self)))
            .or_else(|| step.default_answer.clone())
    }

    /// Resolve select options whose valid values depend on earlier answers.
    /// Model configuration deliberately exposes only models for its selected
    /// provider; the stored answer remains provider-qualified so existing
    /// model-scope write resolution stays unambiguous.
    pub fn select_options(&self) -> Vec<SelectOption> {
        let Some(step) = self.current_step() else {
            return Vec::new();
        };
        let StepKind::Select { options } = &step.kind else {
            return Vec::new();
        };
        if step.id != "model" {
            return options.clone();
        }
        let Some(context) = self.descriptor.model_context.as_ref() else {
            return options.clone();
        };
        let provider = model_provider_answer(self).or_else(|| context.default_provider.clone());
        let Some(provider) = provider else {
            return Vec::new();
        };
        let prefix = format!("{provider}:");
        context
            .models
            .keys()
            .filter(|model_ref| model_ref.starts_with(&prefix))
            .filter_map(|model_ref| {
                let (_, model) = model_ref.split_once(':')?;
                Some(SelectOption {
                    id: model_ref.clone().into(),
                    label: model.to_string().into(),
                    description: "Configure this exact provider/model pair".into(),
                })
            })
            .collect()
    }

    pub fn help(&self) -> Cow<'_, str> {
        let Some(step) = self.current_step() else {
            return Cow::Borrowed("");
        };
        if let Some(help_hook) = step.help_hook
            && let Some(help) = help_hook(self)
        {
            return Cow::Owned(help);
        }
        Cow::Borrowed(step.help)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderWizardStep {
    Template,
    ProviderId,
    Url,
    Headers,
    AuthMethod,
    ApiKey,
    EnvVar,
    CopilotAuth,
    GrokOAuth,
    CodexOAuth,
    Saving,
    TestKeyChoice,
    TestKey,
    TestSkipped,
    Fetching,
    Done,
}

impl ProviderWizardStep {
    pub const ALL: [Self; 16] = [
        Self::Template,
        Self::ProviderId,
        Self::Url,
        Self::Headers,
        Self::AuthMethod,
        Self::ApiKey,
        Self::EnvVar,
        Self::CopilotAuth,
        Self::GrokOAuth,
        Self::CodexOAuth,
        Self::Saving,
        Self::TestKeyChoice,
        Self::TestKey,
        Self::TestSkipped,
        Self::Fetching,
        Self::Done,
    ];
    pub const fn source_id(self) -> &'static str {
        match self {
            Self::Template => "template",
            Self::ProviderId => "id",
            Self::Url => "url",
            Self::Headers => "headers",
            Self::AuthMethod => "auth-method",
            Self::ApiKey => "api-key",
            Self::EnvVar => "env-var",
            Self::CopilotAuth => "copilot-auth",
            Self::GrokOAuth => "grok-oauth",
            Self::CodexOAuth => "codex-oauth",
            Self::Saving => "saving",
            Self::TestKeyChoice => "test-key-choice",
            Self::TestKey => "test-key",
            Self::TestSkipped => "test-skipped",
            Self::Fetching => "fetching",
            Self::Done => "done",
        }
    }

    fn from_source_id(id: &str) -> Self {
        match id {
            "template" => Self::Template,
            "id" => Self::ProviderId,
            "url" => Self::Url,
            "headers" => Self::Headers,
            "auth-method" => Self::AuthMethod,
            "api-key" => Self::ApiKey,
            "env-var" => Self::EnvVar,
            "copilot-auth" => Self::CopilotAuth,
            "grok-oauth" => Self::GrokOAuth,
            "codex-oauth" => Self::CodexOAuth,
            "saving" => Self::Saving,
            "test-key-choice" => Self::TestKeyChoice,
            "test-key" => Self::TestKey,
            "test-skipped" => Self::TestSkipped,
            "fetching" => Self::Fetching,
            "done" => Self::Done,
            _ => panic!("provider wizard descriptor used an unsealed step id `{id}`"),
        }
    }
}

pub fn registry() -> Vec<WizardDescriptor> {
    vec![
        provider_descriptor(),
        security_descriptor(),
        model_descriptor_for_config(&crate::config::providers::ProvidersConfig::default()),
    ]
}

pub fn descriptor(id: &str) -> Option<WizardDescriptor> {
    registry().into_iter().find(|wizard| wizard.id == id)
}

pub fn model_descriptor_for_config(
    cfg: &crate::config::providers::ProvidersConfig,
) -> WizardDescriptor {
    model_descriptor_with_selection(cfg, None)
}

pub fn model_descriptor_with_selection(
    cfg: &crate::config::providers::ProvidersConfig,
    preselect: Option<(&str, &str)>,
) -> WizardDescriptor {
    let provider_options = cfg
        .providers
        .keys()
        .map(|id| SelectOption {
            id: id.clone().into(),
            label: id.clone().into(),
            description: "Configure a model from this provider".into(),
        })
        .collect();
    let model_context = model_wizard_context(cfg, preselect);
    WizardDescriptor {
        id: MODEL_WIZARD_ID,
        title: "Configure model",
        description: "Set trust, capabilities, limits, thinking, delegation, and default model",
        write_policy: WritePolicy::CommitAtEnd,
        model_context: Some(model_context),
        steps: vec![
            StepDescriptor {
                id: "provider",
                prompt: "Choose a provider",
                help: "Pick the provider that owns the model you want to configure.",
                help_hook: None,
                kind: StepKind::Select {
                    options: provider_options,
                },
                default_answer: None,
                prefill: Some(model_provider_prefill),
                validate: Some(validate_select),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "model",
                prompt: "Choose a model",
                help: "Only models configured for the selected provider are shown.",
                help_hook: None,
                kind: StepKind::Select {
                    // Resolved from the provider answer by `select_options`.
                    // Do not restore an all-provider static list here.
                    options: Vec::new(),
                },
                default_answer: None,
                prefill: Some(model_ref_prefill),
                validate: Some(validate_model_ref_matches_provider),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "trust",
                prompt: "Provider trust (data custody)",
                help: "Data custody only, independent of locality. untrusted: inference requests are redacted · trusted: inference requests may be sent raw, including secrets and environment values. Warning: marking an external provider trusted sends that provider raw secrets and environment values. Exports and client display stay redacted either way. Provider default is shown by inheritance.",
                help_hook: Some(model_trust_help),
                kind: StepKind::Select {
                    options: vec![
                        SelectOption {
                            id: "untrusted".into(),
                            label: "untrusted".into(),
                            description: "Redact inference requests (default)".into(),
                        },
                        SelectOption {
                            id: "trusted".into(),
                            label: "trusted".into(),
                            description:
                                "Send inference requests raw, including secrets and environment values; meant for self-hosted or no-log endpoints"
                                    .into(),
                        },
                    ],
                },
                default_answer: None,
                prefill: Some(model_trust_prefill),
                validate: Some(validate_model_trust_answer),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "capabilities",
                prompt: "Input and request capabilities",
                help: "Leave detected values unchanged to keep Auto. Toggle only values you know are wrong.",
                help_hook: None,
                kind: StepKind::MultiToggle {
                    options: vec![
                        SelectOption {
                            id: "images".into(),
                            label: "image input".into(),
                            description: "Supports image input parts".into(),
                        },
                        SelectOption {
                            id: "tools".into(),
                            label: "tool calling".into(),
                            description: "Supports tool/function calling".into(),
                        },
                        SelectOption {
                            id: "reasoning".into(),
                            label: "reasoning".into(),
                            description: "Supports reasoning/thinking controls".into(),
                        },
                        SelectOption {
                            id: "structured_outputs".into(),
                            label: "structured outputs".into(),
                            description: "Supports JSON-schema structured outputs".into(),
                        },
                    ],
                },
                default_answer: None,
                prefill: Some(model_capabilities_prefill),
                validate: Some(validate_model_capability_toggles),
                write: None,
                branch: Some(model_capabilities_branch),
            },
            StepDescriptor {
                id: "context-tokens",
                prompt: "Context window tokens",
                help: "Blank keeps Auto. Enter a number only when detection/defaults are wrong.",
                help_hook: None,
                kind: StepKind::Text,
                default_answer: None,
                prefill: Some(model_context_tokens_prefill),
                validate: Some(validate_optional_u32),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "max-output-tokens",
                prompt: "Max output tokens",
                help: "Blank keeps Auto. Enter a number only when detection/defaults are wrong.",
                help_hook: None,
                kind: StepKind::Text,
                default_answer: None,
                prefill: Some(model_max_output_tokens_prefill),
                validate: Some(validate_optional_u32),
                write: None,
                branch: Some(model_thinking_branch),
            },
            StepDescriptor {
                id: "thinking",
                prompt: "Default thinking mode",
                help: "Active /model selections still win. This model default is used only when the active selection does not pin thinking.",
                help_hook: None,
                kind: StepKind::Select {
                    options: vec![
                        SelectOption {
                            id: "inherit".into(),
                            label: "inherit".into(),
                            description: "No model-level default".into(),
                        },
                        SelectOption {
                            id: "off".into(),
                            label: "off".into(),
                            description: "Disable legacy thinking mode".into(),
                        },
                        SelectOption {
                            id: "low".into(),
                            label: "low".into(),
                            description: "Low thinking mode".into(),
                        },
                        SelectOption {
                            id: "medium".into(),
                            label: "medium".into(),
                            description: "Medium thinking mode".into(),
                        },
                        SelectOption {
                            id: "high".into(),
                            label: "high".into(),
                            description: "High thinking mode".into(),
                        },
                    ],
                },
                default_answer: None,
                prefill: Some(model_thinking_prefill),
                validate: Some(validate_thinking_mode_answer),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "subagent-flags",
                prompt: "Subagent behavior",
                help: "Toggle whether this model can be spawned as a subagent and whether it can spawn subagents.",
                help_hook: None,
                kind: StepKind::MultiToggle {
                    options: vec![
                        SelectOption {
                            id: "subagent_invokable".into(),
                            label: "spawn as subagent".into(),
                            description: "This model may be selected for subagents".into(),
                        },
                        SelectOption {
                            id: "can_delegate".into(),
                            label: "can spawn subagents".into(),
                            description: "This model receives delegation affordances".into(),
                        },
                    ],
                },
                default_answer: None,
                prefill: Some(model_subagent_prefill),
                validate: Some(validate_model_subagent_toggles),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "default-model",
                prompt: "Make this the active/default model?",
                help: "Affects future model resolution; it does not hijack existing live sessions.",
                help_hook: None,
                kind: StepKind::Confirm,
                default_answer: None,
                prefill: Some(model_make_default_prefill),
                validate: None,
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "system-prompt-choice",
                prompt: "Model-specific system prompt",
                help: "Skip, or enter model-specific instructions applied to new root sessions.",
                help_hook: None,
                kind: StepKind::Select {
                    options: vec![
                        SelectOption {
                            id: "skip".into(),
                            label: "skip".into(),
                            description: "Leave model-specific instructions unchanged".into(),
                        },
                        SelectOption {
                            id: "set".into(),
                            label: "set prompt".into(),
                            description: "Enter model-specific instructions now".into(),
                        },
                    ],
                },
                default_answer: Some(WizardAnswer::Select("skip".to_string())),
                prefill: None,
                validate: Some(validate_select),
                write: None,
                branch: Some(model_system_prompt_branch),
            },
            StepDescriptor {
                id: "system-prompt",
                prompt: "System prompt text",
                help: "Blank clears the model-specific prompt.",
                help_hook: None,
                kind: StepKind::Text,
                default_answer: None,
                prefill: Some(model_system_prompt_prefill),
                validate: None,
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "model-save",
                prompt: "Ready to save model settings",
                help: "Only changed model-scope values are written. Press Enter to save; Esc discards.",
                help_hook: None,
                kind: StepKind::Action {
                    progress: "[Save settings]",
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

fn model_wizard_context(
    cfg: &crate::config::providers::ProvidersConfig,
    preselect: Option<(&str, &str)>,
) -> ModelWizardContext {
    use crate::config::providers::CapabilityStatus;

    let mut default_provider = None;
    let mut default_model_ref = None;
    let mut provider_trust_defaults = BTreeMap::new();
    let mut models = BTreeMap::new();
    for (provider_id, provider) in &cfg.providers {
        if default_provider.is_none() {
            default_provider = Some(provider_id.clone());
        }
        provider_trust_defaults.insert(
            provider_id.clone(),
            cfg.provider_trust_default(provider_id.as_str()),
        );
        for model in &provider.models {
            let model_ref = format!("{provider_id}:{}", model.id);
            if default_model_ref.is_none() {
                default_model_ref = Some(model_ref.clone());
            }
            let caps = cfg.resolve_effective_model_capabilities(
                provider_id,
                &model.id,
                cfg.resolution_generation,
            );
            let capabilities = [
                (caps.supports_image_input(), "images"),
                (
                    matches!(caps.tool_calling, CapabilityStatus::Supported),
                    "tools",
                ),
                (
                    matches!(caps.reasoning, CapabilityStatus::Supported),
                    "reasoning",
                ),
                (
                    matches!(caps.structured_outputs, CapabilityStatus::Supported),
                    "structured_outputs",
                ),
            ]
            .into_iter()
            .filter_map(|(enabled, id)| enabled.then_some(id.to_string()))
            .collect();
            models.insert(
                model_ref.clone(),
                ModelWizardPrefill {
                    trust: cfg.resolve_trust(provider_id, &model.id),
                    capabilities,
                    context_tokens: caps.context_tokens,
                    max_output_tokens: caps.max_output_tokens,
                    thinking: cfg.resolve_default_thinking_mode(provider_id, &model.id),
                    subagent_invokable: cfg.resolve_subagent_invokable(provider_id, &model.id),
                    can_delegate: cfg.resolve_can_delegate(provider_id, &model.id),
                    make_default: cfg.active_model.as_ref().is_some_and(|active| {
                        active.provider == provider_id.as_str() && active.model == model.id.as_str()
                    }),
                    system_prompt: cfg
                        .resolve_model_system_prompt(provider_id, &model.id)
                        .map(str::to_string),
                },
            );
            if cfg.active_model.as_ref().is_some_and(|active| {
                active.provider == provider_id.as_str() && active.model == model.id.as_str()
            }) {
                default_provider = Some(provider_id.clone());
                default_model_ref = Some(model_ref);
            }
        }
    }
    if let Some((provider, model)) = preselect {
        let model_ref = format!("{provider}:{model}");
        if models.contains_key(&model_ref) {
            default_provider = Some(provider.to_string());
            default_model_ref = Some(model_ref);
        }
    }
    ModelWizardContext {
        default_provider,
        default_model_ref,
        provider_trust_defaults,
        models,
    }
}

pub fn provider_descriptor() -> WizardDescriptor {
    provider_descriptor_with_template(None)
}

pub fn provider_descriptor_with_template(default_template: Option<&str>) -> WizardDescriptor {
    use crate::providers::TEMPLATES;

    let template_options = TEMPLATES
        .iter()
        .map(|template| SelectOption {
            id: template.id.into(),
            label: template.display.into(),
            description: template.hint.unwrap_or("Provider template").into(),
        })
        .collect();
    WizardDescriptor {
        id: PROVIDER_WIZARD_ID,
        title: "Add provider",
        description: "Configure an inference provider and its authentication",
        write_policy: WritePolicy::PerStep,
        model_context: None,
        steps: vec![
            StepDescriptor {
                id: ProviderWizardStep::Template.source_id(),
                prompt: "Choose a provider template",
                help: "The template pre-fills the provider id, URL, and authentication shape.",
                help_hook: None,
                kind: StepKind::Select {
                    options: template_options,
                },
                default_answer: default_template.map(|id| WizardAnswer::Select(id.to_string())),
                prefill: None,
                validate: Some(validate_select),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: ProviderWizardStep::ProviderId.source_id(),
                prompt: "Provider id",
                help: "Use lowercase letters, digits, `-`, or `_`.",
                help_hook: None,
                kind: StepKind::Text,
                default_answer: None,
                prefill: Some(provider_id_prefill),
                validate: Some(validate_provider_id),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: ProviderWizardStep::Url.source_id(),
                prompt: "Base URL",
                help: "The endpoint must start with http:// or https://.",
                help_hook: None,
                kind: StepKind::Text,
                default_answer: None,
                prefill: Some(provider_url_prefill),
                validate: Some(validate_provider_url),
                write: None,
                branch: Some(provider_auth_branch),
            },
            action_step(
                ProviderWizardStep::Headers.source_id(),
                "Advanced: edit HTTP headers",
                "Editing provider headers…",
            ),
            StepDescriptor {
                id: ProviderWizardStep::AuthMethod.source_id(),
                prompt: "How do you want to provide the API key?",
                help: "Paste stores the key in Cockpit's credential store; env var keeps a $VAR reference; advanced opens raw headers.",
                help_hook: None,
                kind: StepKind::Select {
                    options: vec![
                        SelectOption {
                            id: "paste-key".into(),
                            label: "Paste key".into(),
                            description: "Store a masked key as a $secret: reference".into(),
                        },
                        SelectOption {
                            id: "env-var".into(),
                            label: "Use env var".into(),
                            description: "Write a $VAR reference and keep the key in your shell"
                                .into(),
                        },
                        SelectOption {
                            id: "advanced-headers".into(),
                            label: "Advanced headers".into(),
                            description: "Edit HTTP headers directly".into(),
                        },
                    ],
                },
                default_answer: Some(WizardAnswer::Select("paste-key".to_string())),
                prefill: None,
                validate: Some(validate_select),
                write: None,
                branch: Some(provider_auth_method_branch),
            },
            StepDescriptor {
                id: ProviderWizardStep::ApiKey.source_id(),
                prompt: "Paste API key",
                help: "Input is masked. Surrounding whitespace is trimmed before storage.",
                help_hook: None,
                kind: StepKind::Secret,
                default_answer: None,
                prefill: None,
                validate: Some(validate_api_key),
                write: None,
                branch: Some(action_to_saving),
            },
            StepDescriptor {
                id: ProviderWizardStep::EnvVar.source_id(),
                prompt: "Environment variable name",
                help: "The provider header will reference this variable with $VAR.",
                help_hook: None,
                kind: StepKind::Text,
                default_answer: None,
                prefill: Some(provider_env_var_prefill),
                validate: Some(validate_env_var_name),
                write: None,
                branch: Some(action_to_saving),
            },
            action_step(
                ProviderWizardStep::CopilotAuth.source_id(),
                "Configure GitHub authentication",
                "Configuring GitHub authentication…",
            ),
            action_step(
                ProviderWizardStep::GrokOAuth.source_id(),
                "Sign in to Grok",
                "Waiting for browser authorization…",
            ),
            action_step(
                ProviderWizardStep::CodexOAuth.source_id(),
                "Sign in to Codex",
                "Waiting for device authorization…",
            ),
            StepDescriptor {
                id: ProviderWizardStep::Saving.source_id(),
                prompt: "Save provider",
                help: "The provider is written atomically at this step.",
                help_hook: None,
                kind: StepKind::Action {
                    progress: "Saving provider…",
                },
                default_answer: None,
                prefill: None,
                validate: None,
                write: None,
                branch: Some(provider_after_save_branch),
            },
            StepDescriptor {
                id: ProviderWizardStep::TestKeyChoice.source_id(),
                prompt: "Test key now?",
                help: "Default: test now. Choose skip-test to save without validation.",
                help_hook: None,
                kind: StepKind::Select {
                    options: vec![
                        SelectOption {
                            id: "test".into(),
                            label: "Test key".into(),
                            description: "Validate credentials now".into(),
                        },
                        SelectOption {
                            id: "skip-test".into(),
                            label: "Skip test".into(),
                            description: "Save now and validate on first use".into(),
                        },
                    ],
                },
                default_answer: Some(WizardAnswer::Select("test".to_string())),
                prefill: None,
                validate: Some(validate_select),
                write: None,
                branch: Some(provider_test_choice_branch),
            },
            action_step(
                ProviderWizardStep::TestKey.source_id(),
                "Test key",
                "Testing provider credentials…",
            ),
            StepDescriptor {
                id: ProviderWizardStep::TestSkipped.source_id(),
                prompt: "key saved but unverified — it will be tested on your first message.",
                help: "Continue to finish provider setup.",
                help_hook: None,
                kind: StepKind::Info,
                default_answer: None,
                prefill: None,
                validate: None,
                write: None,
                branch: Some(fetching_to_done),
            },
            action_step(
                ProviderWizardStep::Fetching.source_id(),
                "Fetch models",
                "Fetching /models…",
            ),
            StepDescriptor {
                id: ProviderWizardStep::Done.source_id(),
                prompt: "Provider setup complete",
                help: "Continue to return to the provider list.",
                help_hook: None,
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
    security_descriptor_for_config_with_caps(
        &crate::config::extended::ExtendedConfig::default(),
        &crate::daemon::session_worker::unpublished_host_capability_snapshot(),
    )
}

pub fn security_descriptor_for_config(
    current: &crate::config::extended::ExtendedConfig,
) -> WizardDescriptor {
    security_descriptor_for_config_with_caps(
        current,
        &crate::daemon::session_worker::unpublished_host_capability_snapshot(),
    )
}

pub fn security_descriptor_for_config_with_caps(
    current: &crate::config::extended::ExtendedConfig,
    caps: &cockpit_proto::HostCapabilitySnapshot,
) -> WizardDescriptor {
    let (sandbox_options, sandbox_default) =
        sandbox_select_options(current.sandbox.default_mode, caps);
    WizardDescriptor {
        id: SECURITY_WIZARD_ID,
        title: "Security posture",
        description: "Review sandboxing, approvals, redaction, and workspace trust",
        write_policy: WritePolicy::CommitAtEnd,
        model_context: None,
        steps: vec![
            StepDescriptor {
                id: "sandbox",
                prompt: "How should Cockpit confine shell commands by default?",
                help: "Keep the host shell sandbox unless you specifically need container isolation or unconfined commands. `off` means commands the model runs are unconfined. Container rows are omitted when docker/podman is not available. Host sandbox is omitted when the host capability is down.",
                help_hook: None,
                kind: StepKind::Select {
                    options: sandbox_options,
                },
                default_answer: Some(WizardAnswer::Select(sandbox_default)),
                prefill: None,
                validate: Some(validate_sandbox_mode),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "approval",
                prompt: "How should commands that leave the sandbox be approved?",
                help: "Manual asks you before a command leaves the sandbox. Auto lets the utility model approve when possible and asks when unsafe or unavailable. Yolo runs unprompted. Remembered command/path grants can be once, session, project, or global; project/global grants are machine-local.",
                help_hook: None,
                kind: StepKind::Select {
                    options: vec![
                        SelectOption {
                            id: current.default_approval_mode.as_str().into(),
                            label: "Keep current approval mode".into(),
                            description: "Recommended default is manual. You approve anything that needs to leave the sandbox.".into(),
                        },
                        SelectOption {
                            id: "auto".into(),
                            label: "auto".into(),
                            description: "Let the utility model approve sandbox escapes when possible; ask when unsafe or unavailable.".into(),
                        },
                        SelectOption {
                            id: "yolo".into(),
                            label: "yolo".into(),
                            description: "Run commands without approval prompts.".into(),
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
                id: "redaction",
                prompt: "Minimum secret length for redaction",
                help: "For untrusted models, Cockpit redacts known secrets from your environment and Cockpit's secret store. Keep 8 unless short secrets are common in your workflow.",
                help_hook: None,
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
                help_hook: None,
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
                help_hook: None,
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

fn sandbox_select_options(
    current: crate::tools::sandbox_mode::SandboxMode,
    caps: &cockpit_proto::HostCapabilitySnapshot,
) -> (Vec<SelectOption>, String) {
    use crate::daemon::session_worker::sandbox_mode_selectable;
    use crate::tools::sandbox_mode::SandboxMode;

    let current_selectable = sandbox_mode_selectable(current, caps);
    let host_on = sandbox_mode_selectable(SandboxMode::Sandbox, caps);
    let container_on = sandbox_mode_selectable(SandboxMode::Container, caps);

    let mut options = Vec::new();
    if current_selectable {
        options.push(SelectOption {
            id: sandbox_mode_id(current).into(),
            label: "Keep current sandbox setting".into(),
            description: if current == SandboxMode::Sandbox {
                "Recommended default is sandbox. Commands run inside the OS shell sandbox when available.".into()
            } else {
                "Keep the sandbox mode already stored in config.".into()
            },
        });
    }
    if host_on && current != SandboxMode::Sandbox {
        options.push(SelectOption {
            id: "sandbox".into(),
            label: "sandbox".into(),
            description: "Run commands inside the OS shell sandbox.".into(),
        });
    }
    if container_on {
        if current != SandboxMode::Container {
            options.push(SelectOption {
                id: "container".into(),
                label: "container".into(),
                description: "Run commands in a Docker/Podman container.".into(),
            });
        }
        if current != SandboxMode::ContainerReadonly {
            options.push(SelectOption {
                id: "container-readonly".into(),
                label: "container-readonly".into(),
                description: "Run in a container with the project mounted read-only.".into(),
            });
        }
    }
    if current != SandboxMode::Off || !current_selectable {
        options.push(SelectOption {
            id: "off".into(),
            label: "off".into(),
            description: "Unconfined: commands the model runs are not sandboxed.".into(),
        });
    }

    let default_id = if current_selectable {
        sandbox_mode_id(current).to_string()
    } else if host_on {
        "sandbox".to_string()
    } else {
        "off".to_string()
    };
    (options, default_id)
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

pub fn min_secret_length_answer(run: &WizardRun) -> Option<usize> {
    let WizardAnswer::Text(value) = run.answer("redaction")? else {
        return None;
    };
    value.trim().parse().ok()
}

pub fn sandbox_mode_answer(run: &WizardRun) -> Option<crate::tools::sandbox_mode::SandboxMode> {
    let WizardAnswer::Select(value) = run.answer("sandbox")? else {
        return None;
    };
    sandbox_mode_from_id(value)
}

pub fn approval_mode_answer(run: &WizardRun) -> Option<crate::config::extended::ApprovalMode> {
    let WizardAnswer::Select(value) = run.answer("approval")? else {
        return None;
    };
    approval_mode_from_id(value)
}

pub fn model_provider_answer(run: &WizardRun) -> Option<String> {
    let WizardAnswer::Select(value) = run.answer("provider")? else {
        return None;
    };
    Some(value.to_string())
}

pub fn model_ref_answer(run: &WizardRun) -> Option<(String, String)> {
    let WizardAnswer::Select(value) = run.answer("model")? else {
        return None;
    };
    let (provider, model) = value.split_once(':')?;
    Some((provider.to_string(), model.to_string()))
}

pub fn model_trust_answer(run: &WizardRun) -> Option<crate::config::providers::ModelTrust> {
    let WizardAnswer::Select(value) = run.answer("trust")? else {
        return None;
    };
    model_trust_from_id(value)
}

pub fn model_capability_answers(run: &WizardRun) -> std::collections::BTreeSet<String> {
    let Some(WizardAnswer::MultiToggle(values)) = run.answer("capabilities") else {
        return std::collections::BTreeSet::new();
    };
    values.iter().cloned().collect()
}

pub fn model_subagent_answers(run: &WizardRun) -> std::collections::BTreeSet<String> {
    let Some(WizardAnswer::MultiToggle(values)) = run.answer("subagent-flags") else {
        return std::collections::BTreeSet::new();
    };
    values.iter().cloned().collect()
}

pub fn model_context_tokens_answer(run: &WizardRun) -> Option<u32> {
    optional_u32_answer(run, "context-tokens")
}

pub fn model_max_output_tokens_answer(run: &WizardRun) -> Option<u32> {
    optional_u32_answer(run, "max-output-tokens")
}

pub fn model_default_thinking_answer(
    run: &WizardRun,
) -> Option<Option<crate::config::providers::ThinkingMode>> {
    let WizardAnswer::Select(value) = run.answer("thinking")? else {
        return None;
    };
    if value == "inherit" {
        Some(None)
    } else {
        Some(thinking_mode_from_id(value))
    }
}

pub fn model_make_default_answer(run: &WizardRun) -> bool {
    matches!(
        run.answer("default-model"),
        Some(WizardAnswer::Confirm(true))
    )
}

pub fn model_system_prompt_answer(run: &WizardRun) -> Option<Option<String>> {
    let Some(WizardAnswer::Select(choice)) = run.answer("system-prompt-choice") else {
        return None;
    };
    if choice != "set" {
        return None;
    }
    let Some(WizardAnswer::Text(value)) = run.answer("system-prompt") else {
        return Some(None);
    };
    let trimmed = value.trim();
    Some((!trimmed.is_empty()).then(|| value.clone()))
}

fn optional_u32_answer(run: &WizardRun, id: &str) -> Option<u32> {
    let WizardAnswer::Text(value) = run.answer(id)? else {
        return None;
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        trimmed.parse().ok()
    }
}

pub(crate) fn model_trust_from_id(id: &str) -> Option<crate::config::providers::ModelTrust> {
    Some(match id {
        "trusted" => crate::config::providers::ModelTrust::Trusted,
        "untrusted" => crate::config::providers::ModelTrust::Untrusted,
        _ => return None,
    })
}

pub(crate) fn thinking_mode_from_id(id: &str) -> Option<crate::config::providers::ThinkingMode> {
    Some(match id {
        "off" => crate::config::providers::ThinkingMode::Off,
        "low" => crate::config::providers::ThinkingMode::Low,
        "medium" => crate::config::providers::ThinkingMode::Medium,
        "high" => crate::config::providers::ThinkingMode::High,
        _ => return None,
    })
}

fn model_trust_id(trust: crate::config::providers::ModelTrust) -> &'static str {
    match trust {
        crate::config::providers::ModelTrust::Trusted => "trusted",
        crate::config::providers::ModelTrust::Untrusted => "untrusted",
    }
}

fn thinking_mode_id(mode: crate::config::providers::ThinkingMode) -> &'static str {
    match mode {
        crate::config::providers::ThinkingMode::Off => "off",
        crate::config::providers::ThinkingMode::Low => "low",
        crate::config::providers::ThinkingMode::Medium => "medium",
        crate::config::providers::ThinkingMode::High => "high",
    }
}

fn action_step(id: &'static str, prompt: &'static str, progress: &'static str) -> StepDescriptor {
    StepDescriptor {
        id,
        prompt,
        help: progress,
        help_hook: None,
        kind: StepKind::Action { progress },
        default_answer: None,
        prefill: None,
        validate: None,
        write: None,
        branch: Some(match id {
            "fetching" | "test-key" => fetching_to_done,
            _ => action_to_saving,
        }),
    }
}

fn validate_select(_: &WizardRun, answer: &WizardAnswer) -> std::result::Result<(), String> {
    match answer {
        WizardAnswer::Select(value) if !value.is_empty() => Ok(()),
        _ => Err("choose one option".to_string()),
    }
}

fn validate_model_trust_answer(
    _: &WizardRun,
    answer: &WizardAnswer,
) -> std::result::Result<(), String> {
    let WizardAnswer::Select(value) = answer else {
        return Err("choose trusted or untrusted".to_string());
    };
    model_trust_from_id(value)
        .map(|_| ())
        .ok_or_else(|| "choose trusted or untrusted".to_string())
}

fn validate_thinking_mode_answer(
    _: &WizardRun,
    answer: &WizardAnswer,
) -> std::result::Result<(), String> {
    let WizardAnswer::Select(value) = answer else {
        return Err("choose inherit, off, low, medium, or high".to_string());
    };
    if value == "inherit" || thinking_mode_from_id(value).is_some() {
        Ok(())
    } else {
        Err("choose inherit, off, low, medium, or high".to_string())
    }
}

fn validate_optional_u32(_: &WizardRun, answer: &WizardAnswer) -> std::result::Result<(), String> {
    let WizardAnswer::Text(value) = answer else {
        return Err("enter a number or leave blank".to_string());
    };
    if value.trim().is_empty() || value.trim().parse::<u32>().is_ok_and(|v| v > 0) {
        Ok(())
    } else {
        Err("enter a positive number or leave blank".to_string())
    }
}

fn validate_known_toggles(
    answer: &WizardAnswer,
    allowed: &[&str],
) -> std::result::Result<(), String> {
    let WizardAnswer::MultiToggle(values) = answer else {
        return Err("toggle zero or more listed ids".to_string());
    };
    for value in values {
        if !allowed.iter().any(|allowed| allowed == value) {
            return Err(format!("unknown toggle `{value}`"));
        }
    }
    Ok(())
}

fn validate_model_capability_toggles(
    _: &WizardRun,
    answer: &WizardAnswer,
) -> std::result::Result<(), String> {
    validate_known_toggles(
        answer,
        &["images", "tools", "reasoning", "structured_outputs"],
    )
}

fn validate_model_subagent_toggles(
    _: &WizardRun,
    answer: &WizardAnswer,
) -> std::result::Result<(), String> {
    validate_known_toggles(answer, &["subagent_invokable", "can_delegate"])
}

fn validate_model_ref_matches_provider(
    run: &WizardRun,
    answer: &WizardAnswer,
) -> std::result::Result<(), String> {
    let WizardAnswer::Select(value) = answer else {
        return Err("choose a model".to_string());
    };
    let Some((provider, model)) = value.split_once(':') else {
        return Err("model must be provider:model".to_string());
    };
    if model.is_empty() {
        return Err("model id cannot be empty".to_string());
    }
    if let Some(WizardAnswer::Select(selected_provider)) = run.answer("provider")
        && selected_provider != provider
    {
        return Err(format!(
            "choose a model from provider `{selected_provider}`"
        ));
    }
    Ok(())
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

fn validate_api_key(_: &WizardRun, answer: &WizardAnswer) -> std::result::Result<(), String> {
    match answer {
        WizardAnswer::Secret(value) if !value.trim().is_empty() => Ok(()),
        _ => Err("paste a non-empty API key".to_string()),
    }
}

fn validate_env_var_name(_: &WizardRun, answer: &WizardAnswer) -> std::result::Result<(), String> {
    let WizardAnswer::Text(value) = answer else {
        return Err("enter an environment variable name".to_string());
    };
    let value = value.trim();
    if value.is_empty() {
        return Err("environment variable name cannot be empty".to_string());
    }
    if value.chars().enumerate().all(|(index, ch)| {
        ch == '_' || ch.is_ascii_uppercase() || (index > 0 && ch.is_ascii_digit())
    }) {
        Ok(())
    } else {
        Err("use uppercase letters, digits, and `_` (not starting with a digit)".to_string())
    }
}

pub fn selected_provider_template(
    run: &WizardRun,
) -> Option<&'static crate::providers::ProviderTemplate> {
    let WizardAnswer::Select(id) = run.answer("template")? else {
        return None;
    };
    crate::providers::template_by_id(id)
}

pub fn provider_id_answer(run: &WizardRun) -> Option<String> {
    let WizardAnswer::Text(id) = run.answer("id")? else {
        return None;
    };
    Some(id.trim().to_string())
}

pub fn provider_url_answer(run: &WizardRun) -> Option<String> {
    let WizardAnswer::Text(url) = run.answer("url")? else {
        return None;
    };
    Some(url.trim_end_matches('/').to_string())
}

pub fn provider_entry_from_answers(
    run: &WizardRun,
    headers: Vec<crate::config::providers::HeaderSpec>,
) -> Option<crate::config::providers::ProviderEntry> {
    let template = selected_provider_template(run)?;
    provider_entry_for_template(template, provider_url_answer(run)?, headers).into()
}

pub fn provider_entry_for_template(
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
        usage_probe: None,
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
        can_delegate: None,
        computer_use: None,
        allow_computer_guidance_proposals: None,
        default_thinking_mode: None,
        embeddings: None,
        availability: Default::default(),
        cache: Default::default(),
        shrink: Default::default(),
        context: Default::default(),
        auto_prune: None,
        timeout: Default::default(),
        wire_api: template.default_wire_api,
        backup: None,
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

fn provider_env_var_prefill(run: &WizardRun) -> Option<WizardAnswer> {
    let template = selected_provider_template(run)?;
    Some(WizardAnswer::Text(
        template
            .default_env_var
            .or_else(|| template.env_var_candidates.first().copied())
            .unwrap_or("API_KEY")
            .to_string(),
    ))
}

fn model_context(run: &WizardRun) -> Option<&ModelWizardContext> {
    run.descriptor.model_context.as_ref()
}

fn model_prefill(run: &WizardRun) -> Option<&ModelWizardPrefill> {
    let (provider, model) = model_ref_answer(run)?;
    model_context(run)?
        .models
        .get(&format!("{provider}:{model}"))
}

fn model_trust_help(run: &WizardRun) -> Option<String> {
    let provider = model_provider_answer(run)?;
    let trust = *model_context(run)?.provider_trust_defaults.get(&provider)?;
    Some(format!(
        "provider default: {} · data custody only, independent of locality · untrusted: inference requests are redacted · trusted: inference requests may be sent raw, including secrets and environment values · exports and client display stay redacted either way.",
        model_trust_id(trust)
    ))
}

fn model_provider_prefill(run: &WizardRun) -> Option<WizardAnswer> {
    model_context(run)?
        .default_provider
        .clone()
        .map(WizardAnswer::Select)
}

fn model_ref_prefill(run: &WizardRun) -> Option<WizardAnswer> {
    let context = model_context(run)?;
    if let Some(model_ref) = &context.default_model_ref
        && model_ref
            .split_once(':')
            .is_some_and(|(provider, _)| model_provider_answer(run).as_deref() == Some(provider))
    {
        return Some(WizardAnswer::Select(model_ref.clone()));
    }
    let provider = model_provider_answer(run)?;
    context
        .models
        .keys()
        .find(|model_ref| {
            model_ref
                .split_once(':')
                .is_some_and(|(candidate, _)| candidate == provider)
        })
        .cloned()
        .map(WizardAnswer::Select)
}

fn model_trust_prefill(run: &WizardRun) -> Option<WizardAnswer> {
    Some(WizardAnswer::Select(
        model_trust_id(model_prefill(run)?.trust).to_string(),
    ))
}

fn model_capabilities_prefill(run: &WizardRun) -> Option<WizardAnswer> {
    Some(WizardAnswer::MultiToggle(
        model_prefill(run)?.capabilities.clone(),
    ))
}

fn model_context_tokens_prefill(run: &WizardRun) -> Option<WizardAnswer> {
    Some(WizardAnswer::Text(
        model_prefill(run)?
            .context_tokens
            .map(|value| value.to_string())
            .unwrap_or_default(),
    ))
}

fn model_max_output_tokens_prefill(run: &WizardRun) -> Option<WizardAnswer> {
    Some(WizardAnswer::Text(
        model_prefill(run)?
            .max_output_tokens
            .map(|value| value.to_string())
            .unwrap_or_default(),
    ))
}

fn model_thinking_prefill(run: &WizardRun) -> Option<WizardAnswer> {
    let value = model_prefill(run)?
        .thinking
        .map(thinking_mode_id)
        .unwrap_or("inherit");
    Some(WizardAnswer::Select(value.to_string()))
}

fn model_subagent_prefill(run: &WizardRun) -> Option<WizardAnswer> {
    let prefill = model_prefill(run)?;
    let mut values = Vec::new();
    if prefill.subagent_invokable {
        values.push("subagent_invokable".to_string());
    }
    if prefill.can_delegate {
        values.push("can_delegate".to_string());
    }
    Some(WizardAnswer::MultiToggle(values))
}

fn model_make_default_prefill(run: &WizardRun) -> Option<WizardAnswer> {
    Some(WizardAnswer::Confirm(model_prefill(run)?.make_default))
}

fn model_system_prompt_prefill(run: &WizardRun) -> Option<WizardAnswer> {
    Some(WizardAnswer::Text(
        model_prefill(run)?
            .system_prompt
            .clone()
            .unwrap_or_default(),
    ))
}

fn model_capabilities_branch(_: &WizardRun, _: &WizardAnswer) -> Option<&'static str> {
    Some("context-tokens")
}

fn model_thinking_branch(run: &WizardRun, _: &WizardAnswer) -> Option<&'static str> {
    let selected = model_capability_answers(run);
    if selected.contains("reasoning") {
        Some("thinking")
    } else {
        Some("subagent-flags")
    }
}

fn model_system_prompt_branch(_: &WizardRun, answer: &WizardAnswer) -> Option<&'static str> {
    Some(match answer {
        WizardAnswer::Select(value) if value == "set" => "system-prompt",
        _ => "model-save",
    })
}

fn provider_auth_branch(run: &WizardRun, _: &WizardAnswer) -> Option<&'static str> {
    Some(match selected_provider_template(run)?.id {
        "copilot" => "copilot-auth",
        "grok-oauth" => "grok-oauth",
        "codex-oauth" => "codex-oauth",
        _ if selected_provider_template(run)?.api_key.is_some() => "auth-method",
        _ => "headers",
    })
}

fn provider_auth_method_branch(_: &WizardRun, answer: &WizardAnswer) -> Option<&'static str> {
    Some(match answer {
        WizardAnswer::Select(value) if value == "paste-key" => "api-key",
        WizardAnswer::Select(value) if value == "env-var" => "env-var",
        WizardAnswer::Select(value) if value == "advanced-headers" => "headers",
        _ => "auth-method",
    })
}

fn action_to_saving(_: &WizardRun, _: &WizardAnswer) -> Option<&'static str> {
    Some("saving")
}

fn fetching_to_done(_: &WizardRun, _: &WizardAnswer) -> Option<&'static str> {
    Some("done")
}

fn provider_after_save_branch(run: &WizardRun, _: &WizardAnswer) -> Option<&'static str> {
    Some(if selected_provider_template(run)?.api_key.is_some() {
        "test-key-choice"
    } else if selected_provider_template(run)?.supports_models_endpoint {
        "fetching"
    } else {
        "done"
    })
}

fn provider_test_choice_branch(_: &WizardRun, answer: &WizardAnswer) -> Option<&'static str> {
    Some(match answer {
        WizardAnswer::Select(value) if value == "skip-test" => "test-skipped",
        _ => "test-key",
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    static WRITE_COUNT: AtomicUsize = AtomicUsize::new(0);

    fn write_count_test_lock() -> crate::test_env::TestEnvGuard {
        crate::test_env::lock()
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

    /// The model wizard must present data custody as its own decision, warn
    /// that a trusted external provider receives raw secrets, and never
    /// suggest that locality implies trust.
    #[test]
    fn model_setup_presents_custody_independently() {
        let descriptor =
            model_descriptor_for_config(&crate::config::providers::ProvidersConfig::default());
        let step = |id: &str| {
            descriptor
                .steps
                .iter()
                .find(|step| step.id == id)
                .unwrap_or_else(|| panic!("missing `{id}` step"))
        };

        let trust = step("trust");
        assert!(
            trust.prompt.contains("custody"),
            "trust prompt: {}",
            trust.prompt
        );
        assert!(
            trust
                .help
                .contains("Data custody only, independent of locality"),
            "trust help: {}",
            trust.help
        );
        assert!(
            trust
                .help
                .contains("may be sent raw, including secrets and environment values"),
            "trust help: {}",
            trust.help
        );
        assert!(
            trust.help.contains(
                "marking an external provider trusted sends that provider raw secrets and environment values"
            ),
            "trust help must carry the explicit warning: {}",
            trust.help
        );
        assert!(
            trust
                .help
                .contains("Exports and client display stay redacted either way"),
            "trust help: {}",
            trust.help
        );
        let StepKind::Select { options } = &trust.kind else {
            panic!("trust step must be a select");
        };
        let ids: Vec<&str> = options.iter().map(|option| option.id.as_ref()).collect();
        assert_eq!(
            ids,
            vec!["untrusted", "trusted"],
            "untrusted is the conservative default and is listed first"
        );
        let trusted = options
            .iter()
            .find(|option| option.id == "trusted")
            .expect("trusted option");
        assert!(
            trusted.description.contains("raw"),
            "trusted option must state the custody effect: {}",
            trusted.description
        );
        let untrusted = options
            .iter()
            .find(|option| option.id == "untrusted")
            .expect("untrusted option");
        assert!(
            untrusted
                .description
                .to_ascii_lowercase()
                .contains("redact"),
            "untrusted option must state the redaction effect: {}",
            untrusted.description
        );
        // Neither option may present a class/locality as *implying* a custody
        // class — naming self-hosted endpoints as the intended use of trusted
        // is fine, auto-deriving trust from locality is not.
        for option in options {
            let description = option.description.to_ascii_lowercase();
            for forbidden in ["local models are trusted", "implies trust", "automatically"] {
                assert!(
                    !description.contains(forbidden),
                    "trust option `{}` must not derive custody: {description}",
                    option.id
                );
            }
        }
    }

    fn test_descriptor(policy: WritePolicy) -> WizardDescriptor {
        WizardDescriptor {
            id: "test",
            title: "Test",
            description: "Test wizard",
            write_policy: policy,
            model_context: None,
            steps: vec![
                StepDescriptor {
                    id: "start",
                    prompt: "start",
                    help: "",
                    help_hook: None,
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
                    help_hook: None,
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
                    help_hook: None,
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

    fn model_test_config() -> crate::config::providers::ProvidersConfig {
        let mut cfg = crate::config::providers::ProvidersConfig::default();
        let mut provider_p = crate::config::providers::ProviderEntry {
            url: "http://localhost:1/v1".to_string(),
            ..Default::default()
        };
        provider_p
            .models
            .push(crate::config::providers::ModelEntry {
                id: "m1".to_string(),
                ..Default::default()
            });
        let mut provider_q = crate::config::providers::ProviderEntry {
            url: "http://localhost:2/v1".to_string(),
            trust: Some(crate::config::providers::ModelTrust::Trusted),
            ..Default::default()
        };
        provider_q
            .models
            .push(crate::config::providers::ModelEntry {
                id: "qm".to_string(),
                ..Default::default()
            });
        cfg.providers.insert("p".to_string(), provider_p);
        cfg.providers.insert("q".to_string(), provider_q);
        cfg.active_model = Some(crate::config::providers::ActiveModelRef {
            provider: "p".to_string(),
            model: "m1".to_string(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        });
        cfg
    }

    fn prefill_hook(_: &WizardRun) -> Option<WizardAnswer> {
        Some(WizardAnswer::Text("hook".to_string()))
    }

    fn prefill_test_descriptor() -> WizardDescriptor {
        WizardDescriptor {
            id: "prefill-test",
            title: "Prefill Test",
            description: "Prefill test",
            write_policy: WritePolicy::CommitAtEnd,
            model_context: None,
            steps: vec![
                StepDescriptor {
                    id: "value",
                    prompt: "value",
                    help: "",
                    help_hook: None,
                    kind: StepKind::Text,
                    default_answer: Some(WizardAnswer::Text("default".to_string())),
                    prefill: Some(prefill_hook),
                    validate: None,
                    write: None,
                    branch: None,
                },
                StepDescriptor {
                    id: "done",
                    prompt: "done",
                    help: "",
                    help_hook: None,
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

    #[test]
    fn model_wizard_preselection_prefills_provider_and_model() {
        let cfg = model_test_config();
        let descriptor = model_descriptor_with_selection(&cfg, Some(("q", "qm")));
        let mut run = WizardRun::new(descriptor).unwrap();

        assert_eq!(run.prefill(), Some(WizardAnswer::Select("q".to_string())));
        run.submit(WizardAnswer::Select("q".to_string())).unwrap();
        assert_eq!(
            run.prefill(),
            Some(WizardAnswer::Select("q:qm".to_string()))
        );
        assert_eq!(
            run.select_options()
                .into_iter()
                .map(|option| option.id.into_owned())
                .collect::<Vec<_>>(),
            vec!["q:qm"],
            "the model step only exposes the chosen provider's models"
        );
    }

    #[test]
    fn model_wizard_provider_change_resets_to_that_providers_model_options() {
        let cfg = model_test_config();
        let descriptor = model_descriptor_with_selection(&cfg, Some(("q", "qm")));
        let mut run = WizardRun::new(descriptor).unwrap();

        run.submit(WizardAnswer::Select("p".to_string())).unwrap();
        assert_eq!(
            run.prefill(),
            Some(WizardAnswer::Select("p:m1".to_string())),
            "a valid contextual preselection must not lock a later provider choice"
        );
        assert_eq!(
            run.select_options()
                .into_iter()
                .map(|option| option.id.into_owned())
                .collect::<Vec<_>>(),
            vec!["p:m1"],
        );
    }

    #[test]
    fn model_wizard_unknown_preselection_falls_back() {
        let cfg = model_test_config();
        let descriptor = model_descriptor_with_selection(&cfg, Some(("q", "missing")));
        let mut run = WizardRun::new(descriptor).unwrap();

        assert_eq!(run.prefill(), Some(WizardAnswer::Select("p".to_string())));
        run.submit(WizardAnswer::Select("p".to_string())).unwrap();
        assert_eq!(
            run.prefill(),
            Some(WizardAnswer::Select("p:m1".to_string()))
        );
    }

    #[test]
    fn trust_step_help_shows_resolved_provider_default() {
        let cfg = model_test_config();
        let descriptor = model_descriptor_for_config(&cfg);
        let mut run = WizardRun::new(descriptor).unwrap();
        run.submit(WizardAnswer::Select("q".to_string())).unwrap();
        run.submit(WizardAnswer::Select("q:qm".to_string()))
            .unwrap();
        assert!(run.help().contains("provider default: trusted"));

        let descriptor = model_descriptor_for_config(&cfg);
        let mut run = WizardRun::new(descriptor).unwrap();
        run.submit(WizardAnswer::Select("p".to_string())).unwrap();
        run.submit(WizardAnswer::Select("p:m1".to_string()))
            .unwrap();
        assert!(run.help().contains("provider default: untrusted"));
    }

    #[test]
    fn prefill_hook_wins_over_default_answer() {
        let run = WizardRun::new(prefill_test_descriptor()).unwrap();

        assert_eq!(run.prefill(), Some(WizardAnswer::Text("hook".to_string())));
    }

    #[test]
    fn saved_answer_wins_over_prefill_hook() {
        let mut run = WizardRun::new(prefill_test_descriptor()).unwrap();

        run.submit(WizardAnswer::Text("saved".to_string())).unwrap();
        assert!(run.back());
        assert_eq!(run.prefill(), Some(WizardAnswer::Text("saved".to_string())));
    }

    #[test]
    fn provider_wizard_prefill_precedence_regression() {
        let mut run = WizardRun::new(provider_descriptor_with_template(Some("openai"))).unwrap();

        assert_eq!(
            run.prefill(),
            Some(WizardAnswer::Select("openai".to_string()))
        );
        run.submit(WizardAnswer::Select("openai".to_string()))
            .unwrap();
        assert_eq!(
            run.prefill(),
            Some(WizardAnswer::Text("openai".to_string()))
        );
    }

    #[test]
    fn security_wizard_prefills_current_config() {
        let current = crate::config::extended::ExtendedConfig {
            sandbox: crate::config::extended::SandboxConfig {
                default_mode: crate::tools::sandbox_mode::SandboxMode::ContainerReadonly,
                ..Default::default()
            },
            default_approval_mode: crate::config::extended::ApprovalMode::Yolo,
            redact: crate::config::extended::RedactConfig {
                min_secret_length: 17,
                ..Default::default()
            },
            ..Default::default()
        };
        let caps = crate::daemon::session_worker::sandbox_capability_snapshot(
            cockpit_proto::FeatureCapabilityState::Available,
            cockpit_proto::FeatureCapabilityState::Available,
        );
        let mut run =
            WizardRun::new(security_descriptor_for_config_with_caps(&current, &caps)).unwrap();

        assert_eq!(
            run.prefill(),
            Some(WizardAnswer::Select("container-readonly".to_string()))
        );
        run.submit(WizardAnswer::Select("container-readonly".to_string()))
            .unwrap();
        assert_eq!(
            run.prefill(),
            Some(WizardAnswer::Select("yolo".to_string()))
        );
        run.submit(WizardAnswer::Select("yolo".to_string()))
            .unwrap();
        assert_eq!(run.prefill(), Some(WizardAnswer::Text("17".to_string())));
    }

    fn sandbox_option_ids(descriptor: &WizardDescriptor) -> Vec<String> {
        let sandbox = descriptor
            .steps
            .iter()
            .find(|step| step.id == "sandbox")
            .expect("sandbox step");
        let StepKind::Select { options } = &sandbox.kind else {
            panic!("sandbox step is select");
        };
        options.iter().map(|option| option.id.to_string()).collect()
    }

    fn sandbox_default_id(descriptor: &WizardDescriptor) -> String {
        let sandbox = descriptor
            .steps
            .iter()
            .find(|step| step.id == "sandbox")
            .expect("sandbox step");
        match &sandbox.default_answer {
            Some(WizardAnswer::Select(id)) => id.clone(),
            other => panic!("sandbox default should be select, got {other:?}"),
        }
    }

    #[test]
    fn security_wizard_host_unavailable_defaults_off_and_omits_host_on() {
        let caps = crate::daemon::session_worker::sandbox_capability_snapshot(
            cockpit_proto::FeatureCapabilityState::Missing,
            cockpit_proto::FeatureCapabilityState::Available,
        );
        let descriptor = security_descriptor_for_config_with_caps(
            &crate::config::extended::ExtendedConfig::default(),
            &caps,
        );
        let ids = sandbox_option_ids(&descriptor);
        assert!(!ids.iter().any(|id| id == "sandbox"));
        assert_eq!(sandbox_default_id(&descriptor), "off");
    }

    #[test]
    fn security_wizard_container_unavailable_omits_container_rows() {
        let caps = crate::daemon::session_worker::sandbox_capability_snapshot(
            cockpit_proto::FeatureCapabilityState::Available,
            cockpit_proto::FeatureCapabilityState::Missing,
        );
        let descriptor = security_descriptor_for_config_with_caps(
            &crate::config::extended::ExtendedConfig::default(),
            &caps,
        );
        let ids = sandbox_option_ids(&descriptor);
        assert!(
            !ids.iter()
                .any(|id| id == "container" || id == "container-readonly")
        );
        assert!(ids.iter().any(|id| id == "sandbox"));
        assert_eq!(sandbox_default_id(&descriptor), "sandbox");
    }

    #[test]
    fn security_wizard_failed_or_timeout_treats_capability_as_unavailable() {
        for state in [
            cockpit_proto::FeatureCapabilityState::Failed,
            cockpit_proto::FeatureCapabilityState::Missing,
        ] {
            let caps = crate::daemon::session_worker::sandbox_capability_snapshot(state, state);
            let descriptor = security_descriptor_for_config_with_caps(
                &crate::config::extended::ExtendedConfig::default(),
                &caps,
            );
            let ids = sandbox_option_ids(&descriptor);
            assert!(
                !ids.iter()
                    .any(|id| id == "sandbox" || id == "container" || id == "container-readonly"),
                "state {state:?} must not offer unavailable rows"
            );
            assert_eq!(sandbox_default_id(&descriptor), "off");
        }
    }

    #[test]
    fn security_wizard_both_available_keeps_sandbox_default_and_container_rows() {
        let caps = crate::daemon::session_worker::sandbox_capability_snapshot(
            cockpit_proto::FeatureCapabilityState::Available,
            cockpit_proto::FeatureCapabilityState::Available,
        );
        let descriptor = security_descriptor_for_config_with_caps(
            &crate::config::extended::ExtendedConfig::default(),
            &caps,
        );
        let ids = sandbox_option_ids(&descriptor);
        assert!(ids.iter().any(|id| id == "sandbox"));
        assert!(ids.iter().any(|id| id == "container"));
        assert!(ids.iter().any(|id| id == "container-readonly"));
        assert_eq!(sandbox_default_id(&descriptor), "sandbox");
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
