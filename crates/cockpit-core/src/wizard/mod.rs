//! Renderer-independent declarative wizard descriptors and transition state.
//!
//! Renderers own terminal/TUI concerns. [`WizardRun`] only validates answers,
//! records navigation, selects branches, and applies descriptor write hooks.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow};

pub const PROVIDER_WIZARD_ID: &str = "provider";
pub const SECURITY_WIZARD_ID: &str = "security";
pub const MODEL_WIZARD_ID: &str = "model";

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
    pub(crate) model_context: Option<ModelWizardContext>,
}

#[derive(Clone, Debug)]
pub(crate) struct ModelWizardContext {
    default_provider: Option<String>,
    default_model_ref: Option<String>,
    models: BTreeMap<String, ModelWizardPrefill>,
}

#[derive(Clone, Debug)]
struct ModelWizardPrefill {
    class: crate::config::extended::LlmMode,
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
            .or_else(|| step.prefill.and_then(|prefill| prefill(self)))
            .or_else(|| step.default_answer.clone())
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
    model_descriptor_for_config_with_global(cfg, crate::config::extended::LlmMode::default())
}

pub fn model_descriptor_for_config_with_global(
    cfg: &crate::config::providers::ProvidersConfig,
    global_mode: crate::config::extended::LlmMode,
) -> WizardDescriptor {
    let provider_options = cfg
        .providers
        .keys()
        .map(|id| SelectOption {
            id: leak_static(id.clone()),
            label: leak_static(id.clone()),
            description: "Configure a model from this provider",
        })
        .collect();
    let mut model_options = Vec::new();
    for (provider_id, provider) in &cfg.providers {
        for model in &provider.models {
            let id = format!("{provider_id}:{}", model.id);
            let label = model
                .name
                .as_ref()
                .map(|name| format!("{name} ({provider_id}:{})", model.id))
                .unwrap_or_else(|| id.clone());
            model_options.push(SelectOption {
                id: leak_static(id),
                label: leak_static(label),
                description: "Configure this exact provider/model pair",
            });
        }
    }
    let model_context = model_wizard_context(cfg, global_mode);
    WizardDescriptor {
        id: MODEL_WIZARD_ID,
        title: "Configure model",
        description: "Set class, trust, capabilities, limits, thinking, delegation, and default model",
        write_policy: WritePolicy::CommitAtEnd,
        model_context: Some(model_context),
        steps: vec![
            StepDescriptor {
                id: "provider",
                prompt: "Choose a provider",
                help: "Pick the provider that owns the model you want to configure.",
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
                help: "Model ids are provider-qualified as provider:model.",
                kind: StepKind::Select {
                    options: model_options,
                },
                default_answer: None,
                prefill: Some(model_ref_prefill),
                validate: Some(validate_model_ref_matches_provider),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "class",
                prompt: "Model class",
                help: "Writes a model-level class override only when it differs from the inherited answer.",
                kind: StepKind::Select {
                    options: vec![
                        SelectOption {
                            id: "defensive",
                            label: "defensive",
                            description: "Small/defensive model class",
                        },
                        SelectOption {
                            id: "normal",
                            label: "normal",
                            description: "Default strong-model class",
                        },
                        SelectOption {
                            id: "frontier",
                            label: "frontier",
                            description: "Top-tier/frontier class",
                        },
                    ],
                },
                default_answer: None,
                prefill: Some(model_class_prefill),
                validate: Some(validate_llm_mode_answer),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "trust",
                prompt: "Provider trust",
                help: "provider default is shown by inheritance. untrusted: cockpit redacts known secrets from requests · trusted: requests are sent unredacted.",
                kind: StepKind::Select {
                    options: vec![
                        SelectOption {
                            id: "untrusted",
                            label: "untrusted",
                            description: "Redact known secrets before requests",
                        },
                        SelectOption {
                            id: "trusted",
                            label: "trusted",
                            description: "Self-hosted/trusted endpoint; send requests unredacted",
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
                kind: StepKind::MultiToggle {
                    options: vec![
                        SelectOption {
                            id: "images",
                            label: "image input",
                            description: "Supports image input parts",
                        },
                        SelectOption {
                            id: "tools",
                            label: "tool calling",
                            description: "Supports tool/function calling",
                        },
                        SelectOption {
                            id: "reasoning",
                            label: "reasoning",
                            description: "Supports reasoning/thinking controls",
                        },
                        SelectOption {
                            id: "structured_outputs",
                            label: "structured outputs",
                            description: "Supports JSON-schema structured outputs",
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
                kind: StepKind::Select {
                    options: vec![
                        SelectOption {
                            id: "inherit",
                            label: "inherit",
                            description: "No model-level default",
                        },
                        SelectOption {
                            id: "off",
                            label: "off",
                            description: "Disable legacy thinking mode",
                        },
                        SelectOption {
                            id: "low",
                            label: "low",
                            description: "Low thinking mode",
                        },
                        SelectOption {
                            id: "medium",
                            label: "medium",
                            description: "Medium thinking mode",
                        },
                        SelectOption {
                            id: "high",
                            label: "high",
                            description: "High thinking mode",
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
                kind: StepKind::MultiToggle {
                    options: vec![
                        SelectOption {
                            id: "subagent_invokable",
                            label: "spawn as subagent",
                            description: "This model may be selected for subagents",
                        },
                        SelectOption {
                            id: "can_delegate",
                            label: "can spawn subagents",
                            description: "This model receives delegation affordances",
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
                kind: StepKind::Select {
                    options: vec![
                        SelectOption {
                            id: "skip",
                            label: "skip",
                            description: "Leave model-specific instructions unchanged",
                        },
                        SelectOption {
                            id: "set",
                            label: "set prompt",
                            description: "Enter model-specific instructions now",
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
                kind: StepKind::Text,
                default_answer: None,
                prefill: Some(model_system_prompt_prefill),
                validate: None,
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "model-save",
                prompt: "Apply model settings",
                help: "Only changed model-scope values are written.",
                kind: StepKind::Action {
                    progress: "Applying model settings…",
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
    global_mode: crate::config::extended::LlmMode,
) -> ModelWizardContext {
    use crate::config::providers::CapabilityStatus;

    let mut default_provider = None;
    let mut default_model_ref = None;
    let mut models = BTreeMap::new();
    for (provider_id, provider) in &cfg.providers {
        if default_provider.is_none() {
            default_provider = Some(provider_id.clone());
        }
        for model in &provider.models {
            let model_ref = format!("{provider_id}:{}", model.id);
            if default_model_ref.is_none() {
                default_model_ref = Some(model_ref.clone());
            }
            let caps = cfg.resolve_capabilities(provider_id, &model.id);
            let capabilities = [
                (caps.images == Some(true), "images"),
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
                    class: cfg.resolve_mode(provider_id, &model.id, global_mode),
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
    ModelWizardContext {
        default_provider,
        default_model_ref,
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
        model_context: None,
        steps: vec![
            StepDescriptor {
                id: "template",
                prompt: "Choose a provider template",
                help: "The template pre-fills the provider id, URL, and authentication shape.",
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
                "Advanced: edit HTTP headers",
                "Editing provider headers…",
            ),
            StepDescriptor {
                id: "auth-method",
                prompt: "How do you want to provide the API key?",
                help: "Paste stores the key in Cockpit's credential store; env var keeps a $VAR reference; advanced opens raw headers.",
                kind: StepKind::Select {
                    options: vec![
                        SelectOption {
                            id: "paste-key",
                            label: "Paste key",
                            description: "Store a masked key as a $secret: reference",
                        },
                        SelectOption {
                            id: "env-var",
                            label: "Use env var",
                            description: "Write a $VAR reference and keep the key in your shell",
                        },
                        SelectOption {
                            id: "advanced-headers",
                            label: "Advanced headers",
                            description: "Edit HTTP headers directly",
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
                id: "api-key",
                prompt: "Paste API key",
                help: "Input is masked. Surrounding whitespace is trimmed before storage.",
                kind: StepKind::Secret,
                default_answer: None,
                prefill: None,
                validate: Some(validate_api_key),
                write: None,
                branch: Some(action_to_saving),
            },
            StepDescriptor {
                id: "env-var",
                prompt: "Environment variable name",
                help: "The provider header will reference this variable with $VAR.",
                kind: StepKind::Text,
                default_answer: None,
                prefill: Some(provider_env_var_prefill),
                validate: Some(validate_env_var_name),
                write: None,
                branch: Some(action_to_saving),
            },
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
                branch: Some(provider_after_save_branch),
            },
            StepDescriptor {
                id: "test-key-choice",
                prompt: "Test key now?",
                help: "Default: test now. Choose skip-test to save without validation.",
                kind: StepKind::Select {
                    options: vec![
                        SelectOption {
                            id: "test",
                            label: "Test key",
                            description: "Validate credentials now",
                        },
                        SelectOption {
                            id: "skip-test",
                            label: "Skip test",
                            description: "Save now and validate on first use",
                        },
                    ],
                },
                default_answer: Some(WizardAnswer::Select("test".to_string())),
                prefill: None,
                validate: Some(validate_select),
                write: None,
                branch: Some(provider_test_choice_branch),
            },
            action_step("test-key", "Test key", "Testing provider credentials…"),
            StepDescriptor {
                id: "test-skipped",
                prompt: "key saved but unverified — it will be tested on your first message.",
                help: "Continue to finish provider setup.",
                kind: StepKind::Info,
                default_answer: None,
                prefill: None,
                validate: None,
                write: None,
                branch: Some(fetching_to_done),
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
        model_context: None,
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

pub fn trusted_only_answer(run: &WizardRun) -> Option<bool> {
    let WizardAnswer::Confirm(value) = run.answer("trusted-only")? else {
        return None;
    };
    Some(*value)
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

pub fn model_class_answer(run: &WizardRun) -> Option<crate::config::extended::LlmMode> {
    let WizardAnswer::Select(value) = run.answer("class")? else {
        return None;
    };
    llm_mode_from_id(value)
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

pub(crate) fn llm_mode_from_id(id: &str) -> Option<crate::config::extended::LlmMode> {
    Some(match id {
        "defensive" => crate::config::extended::LlmMode::Defensive,
        "normal" => crate::config::extended::LlmMode::Normal,
        "frontier" => crate::config::extended::LlmMode::Frontier,
        _ => return None,
    })
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

fn llm_mode_id(mode: crate::config::extended::LlmMode) -> &'static str {
    match mode {
        crate::config::extended::LlmMode::Defensive => "defensive",
        crate::config::extended::LlmMode::Normal => "normal",
        crate::config::extended::LlmMode::Frontier => "frontier",
    }
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

fn leak_static(value: String) -> &'static str {
    Box::leak(value.into_boxed_str())
}

fn validate_select(_: &WizardRun, answer: &WizardAnswer) -> std::result::Result<(), String> {
    match answer {
        WizardAnswer::Select(value) if !value.is_empty() => Ok(()),
        _ => Err("choose one option".to_string()),
    }
}

fn validate_llm_mode_answer(
    _: &WizardRun,
    answer: &WizardAnswer,
) -> std::result::Result<(), String> {
    let WizardAnswer::Select(value) = answer else {
        return Err("choose defensive, normal, or frontier".to_string());
    };
    llm_mode_from_id(value)
        .map(|_| ())
        .ok_or_else(|| "choose defensive, normal, or frontier".to_string())
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

fn model_class_prefill(run: &WizardRun) -> Option<WizardAnswer> {
    Some(WizardAnswer::Select(
        llm_mode_id(model_prefill(run)?.class).to_string(),
    ))
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
            model_context: None,
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
