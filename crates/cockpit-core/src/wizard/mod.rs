//! Renderer-independent declarative wizard descriptors and transition state.
//!
//! Renderers own terminal/TUI concerns. [`WizardRun`] only validates answers,
//! records navigation, selects branches, and applies descriptor write hooks.

use std::borrow::Cow;
use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow};

mod apply;

pub use apply::{
    ModelAnswersOutcome, OnboardingConfigRollback, PreparedOnboardingAgent, apply_model_answers,
    apply_security_answers, apply_security_answers_with_caps, apply_setup_wizard_answers,
    apply_setup_wizard_answers_authoritative, capture_onboarding_agent_config,
    compose_wizard_host_capabilities, descriptor_for_cwd, descriptor_for_cwd_with_caps,
    model_descriptor_for_cwd, onboarding_model_descriptor_for_cwd, persist_onboarding_agent_plan,
    prepare_onboarding_agent_answers, prepare_onboarding_agent_answers_for_catalog,
    security_config_path,
};

pub const PROVIDER_WIZARD_ID: &str = "provider";
pub const SECURITY_WIZARD_ID: &str = "security";
pub const MODEL_WIZARD_ID: &str = "model";
pub const ONBOARDING_MODEL_WIZARD_ID: &str = "onboarding-model";
pub const ONBOARDING_PROFILE_WIZARD_ID: &str = "onboarding-profile";
pub const ONBOARDING_AGENT_WIZARD_ID: &str = "onboarding-agent";
pub const ONBOARDING_LIFETIME_WIZARD_ID: &str = "onboarding-lifetime";

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
    /// The onboarding agent picker is the other dependent-select wizard: its
    /// model choices are a function of the agent chosen on the preceding
    /// screen. Keeping that relationship in the descriptor makes it apply to
    /// both renderers and authoritative answer replay.
    pub(crate) onboarding_agent_models: BTreeMap<String, Vec<SelectOption>>,
    /// Immutable catalog identity carried with the rendered picker.  It is
    /// encoded with the answers so authoritative replay fetches this exact
    /// catalog revision instead of resolving `main` a second time.
    pub(crate) onboarding_catalog_revision: Option<String>,
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
        let mut answers = self
            .answers
            .iter()
            .map(|(id, answer)| ((*id).to_string(), answer.clone()))
            .collect::<BTreeMap<_, _>>();
        if let Some(revision) = &self.descriptor.onboarding_catalog_revision {
            answers.insert(
                "__onboarding_catalog_revision".to_string(),
                WizardAnswer::Text(revision.clone()),
            );
        }
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
                .or_else(|| {
                    // The client acknowledges the terminal save action only after
                    // the daemon response. It is the sole answer replay may infer.
                    matches!(&step.kind, StepKind::Action { .. })
                        .then_some(WizardAnswer::Acknowledged)
                })
                .ok_or_else(|| anyhow!("missing answer for wizard step `{}`", step.id))?;
            run.submit(answer)
                .map_err(|error| anyhow!("invalid wizard answer: {error}"))?;
        }
        Ok(run)
    }

    /// Rebuild an interrupted run from the answers accepted before its current
    /// step. Unlike daemon application, resume never infers an action answer:
    /// durable mutations must be dispatched again and acknowledged normally.
    pub fn resume_from_answers_json(descriptor: WizardDescriptor, json: &str) -> Result<Self> {
        let mut answers: BTreeMap<String, WizardAnswer> =
            serde_json::from_str(json).context("deserializing wizard progress")?;
        anyhow::ensure!(
            !answers
                .values()
                .any(|answer| matches!(answer, WizardAnswer::Secret(_))),
            "wizard progress contains a secret answer"
        );
        let mut run = Self::new(descriptor)?;
        while let Some(step) = run.current_step() {
            let Some(answer) = answers.remove(step.id) else {
                break;
            };
            run.submit(answer)
                .map_err(|error| anyhow!("invalid resumed wizard answer: {error}"))?;
        }
        anyhow::ensure!(
            answers.is_empty(),
            "wizard progress contains answers outside the active branch"
        );
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
        if step.id == "default-model" && self.descriptor.id == ONBOARDING_AGENT_WIZARD_ID {
            let Some(WizardAnswer::Select(agent)) = self.answer("agent") else {
                return Vec::new();
            };
            return self
                .descriptor
                .onboarding_agent_models
                .get(agent)
                .cloned()
                .unwrap_or_default();
        }
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
        if matches!(step.kind, StepKind::Select { .. }) {
            let WizardAnswer::Select(value) = &answer else {
                return Err("choose one option".to_string());
            };
            if !self
                .select_options()
                .iter()
                .any(|option| option.id.as_ref() == value.as_str())
            {
                let error = "choose one of the available options".to_string();
                self.error = Some(error.clone());
                return Err(error);
            }
        }
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
    WireApi,
    ProviderId,
    Url,
    Headers,
    AuthMethod,
    ApiKey,
    EnvVar,
    CopyDetectedEnv,
    CopilotAuth,
    GrokOAuth,
    CodexOAuth,
    Saving,
    TestKey,
    Fetching,
    Done,
}

impl ProviderWizardStep {
    pub const ALL: [Self; 16] = [
        Self::Template,
        Self::WireApi,
        Self::ProviderId,
        Self::Url,
        Self::Headers,
        Self::AuthMethod,
        Self::ApiKey,
        Self::EnvVar,
        Self::CopyDetectedEnv,
        Self::CopilotAuth,
        Self::GrokOAuth,
        Self::CodexOAuth,
        Self::Saving,
        Self::TestKey,
        Self::Fetching,
        Self::Done,
    ];
    pub const fn source_id(self) -> &'static str {
        match self {
            Self::Template => "template",
            Self::WireApi => "wire-api",
            Self::ProviderId => "id",
            Self::Url => "url",
            Self::Headers => "headers",
            Self::AuthMethod => "auth-method",
            Self::ApiKey => "api-key",
            Self::EnvVar => "env-var",
            Self::CopyDetectedEnv => "copy-detected-env",
            Self::CopilotAuth => "copilot-auth",
            Self::GrokOAuth => "grok-oauth",
            Self::CodexOAuth => "codex-oauth",
            Self::Saving => "saving",
            Self::TestKey => "test-key",
            Self::Fetching => "fetching",
            Self::Done => "done",
        }
    }

    fn from_source_id(id: &str) -> Self {
        match id {
            "template" => Self::Template,
            "wire-api" => Self::WireApi,
            "id" => Self::ProviderId,
            "url" => Self::Url,
            "headers" => Self::Headers,
            "auth-method" => Self::AuthMethod,
            "api-key" => Self::ApiKey,
            "env-var" => Self::EnvVar,
            "copy-detected-env" => Self::CopyDetectedEnv,
            "copilot-auth" => Self::CopilotAuth,
            "grok-oauth" => Self::GrokOAuth,
            "codex-oauth" => Self::CodexOAuth,
            "saving" => Self::Saving,
            "test-key" => Self::TestKey,
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

/// The small durable profile step shown on every fresh-install onboarding.
/// An empty name is a deliberate skip, not an omitted screen.
pub fn onboarding_profile_descriptor() -> WizardDescriptor {
    WizardDescriptor {
        id: ONBOARDING_PROFILE_WIZARD_ID,
        title: "What should Cockpit call you?",
        description: "Set an optional display name",
        write_policy: WritePolicy::CommitAtEnd,
        model_context: None,
        onboarding_agent_models: BTreeMap::new(),
        onboarding_catalog_revision: None,
        steps: vec![
            StepDescriptor {
                id: "name",
                prompt: "Your name (leave blank to skip)",
                help: "This stays in your global Cockpit config and can be changed later.",
                help_hook: None,
                kind: StepKind::Text,
                default_answer: None,
                prefill: Some(onboarding_name_prefill),
                validate: Some(validate_onboarding_name),
                write: None,
                branch: None,
            },
            action_step(
                "profile-save",
                "Continue to provider setup",
                "Saving your profile…",
                None,
            ),
        ],
    }
}

/// One-time owner-lifetime choice. Persistent is pre-selected, but the user
/// must explicitly continue through this screen before onboarding completes.
pub fn onboarding_lifetime_descriptor() -> WizardDescriptor {
    WizardDescriptor {
        id: ONBOARDING_LIFETIME_WIZARD_ID,
        title: "Background agents",
        description: "Choose what happens after the last Cockpit window closes",
        write_policy: WritePolicy::CommitAtEnd,
        model_context: None,
        onboarding_agent_models: BTreeMap::new(),
        onboarding_catalog_revision: None,
        steps: vec![
            StepDescriptor {
                id: "background-agents",
                prompt: "Keep agents running in the background after I close all windows.",
                help: "On keeps agents and sessions running so you can reattach later. Off uses an ephemeral lifetime: closing the last client stops agents and owned processes.",
                help_hook: None,
                kind: StepKind::Confirm,
                default_answer: Some(WizardAnswer::Confirm(true)),
                prefill: None,
                validate: None,
                write: None,
                branch: None,
            },
            action_step(
                "lifetime-save",
                "Save agent lifetime",
                "Saving agent lifetime…",
                None,
            ),
        ],
    }
}

/// Agent installation and default-selection step. Discovery is filtered by
/// the configured model catalog before the user sees it. Callers resolve the
/// preferred live-or-cached catalog before constructing this descriptor, and
/// the apply boundary pins the resulting first-party revision.
pub fn onboarding_agent_descriptor(
    providers: &crate::config::providers::ProvidersConfig,
    catalog: &crate::daemon::agent_catalog::AgentCatalogIndex,
    catalog_revision: String,
) -> WizardDescriptor {
    let suggestions = catalog.suggestions_for_models(providers);
    let mut agent_options: Vec<SelectOption> = suggestions
        .iter()
        .map(|entry| SelectOption {
            id: entry.catalog.slug.clone().into(),
            label: entry.catalog.display_name.clone().into(),
            description: entry.definition.description.clone().into(),
        })
        .collect();
    let offerings = crate::daemon::agent_installation::setup_offerings(providers);
    let mut onboarding_agent_models: BTreeMap<String, Vec<SelectOption>> = suggestions
        .into_iter()
        .filter_map(|entry| {
            let primary = entry.definition.model_slots.get("primary")?;
            let options =
                crate::agents::ranked_compatible_offerings(primary, &offerings, providers)
                    .into_iter()
                    .map(|offering| SelectOption {
                        id: format!("{}/{}", offering.provider_profile_handle, offering.model_id)
                            .into(),
                        label: format!(
                            "{}/{}",
                            offering.provider_profile_handle, offering.model_id
                        )
                        .into(),
                        description: "Compatible with the selected agent".into(),
                    })
                    .collect();
            Some((entry.catalog.slug.clone(), options))
        })
        .collect();
    // A third-party definition cannot be trusted from a catalog preview. The
    // installer fetches and validates the pinned source before binding; this
    // list merely lets the user nominate an already-configured model for that
    // authoritative compatibility check.
    agent_options.push(SelectOption {
        id: "third-party".into(),
        label: "Install a third-party agent".into(),
        description: "Requires a pinned source and explicit trust confirmation".into(),
    });
    onboarding_agent_models.insert(
        "third-party".to_string(),
        offerings
            .iter()
            .map(|offering| SelectOption {
                id: format!("{}/{}", offering.provider_profile_handle, offering.model_id).into(),
                label: format!("{}/{}", offering.provider_profile_handle, offering.model_id).into(),
                description: "Compatibility is verified from the fetched pinned definition".into(),
            })
            .collect(),
    );
    let mut sidecar_options = vec![SelectOption {
        id: "disabled".into(),
        label: "Disable image sidecar".into(),
        description: "Screenshots will not be sent to a separate vision model".into(),
    }];
    for (provider_id, provider) in &providers.providers {
        for model in &provider.models {
            if !providers
                .resolve_effective_model_capabilities(
                    provider_id,
                    &model.id,
                    providers.resolution_generation,
                )
                .supports_image_input()
            {
                continue;
            }
            let self_hosted = matches!(
                providers.resolve_location(provider_id, &model.id),
                Some(crate::config::providers::ModelLocation::Local)
                    | Some(crate::config::providers::ModelLocation::PrivateRemote)
            );
            let locality = if self_hosted { "local" } else { "remote" };
            sidecar_options.push(SelectOption {
                id: format!("{locality}:{provider_id}/{}", model.id).into(),
                label: format!("{provider_id}/{}", model.id).into(),
                description: if self_hosted {
                    "Local/self-hosted vision model (preferred)".into()
                } else {
                    "Remote vision model; screenshots and image content leave this machine".into()
                },
            });
        }
    }
    let sidecar_default = crate::onboarding_agent::preferred_self_hosted_sidecar(providers)
        .map(|sidecar| {
            WizardAnswer::Select(format!("local:{}/{}", sidecar.provider, sidecar.model))
        })
        .unwrap_or_else(|| WizardAnswer::Select("disabled".into()));
    WizardDescriptor {
        id: ONBOARDING_AGENT_WIZARD_ID,
        title: "Install your coding agent",
        description: "Choose an agent, confirm model trust, configure tools, and select an image sidecar",
        write_policy: WritePolicy::CommitAtEnd,
        model_context: None,
        onboarding_agent_models,
        onboarding_catalog_revision: Some(catalog_revision),
        steps: vec![
            StepDescriptor {
                id: "agent",
                prompt: "Choose an agent compatible with your configured models",
                help: "Cockpit prefers the live FlyCockpit/agents catalog and uses this bundled snapshot when offline.",
                help_hook: None,
                kind: StepKind::Select {
                    options: agent_options,
                },
                default_answer: None,
                prefill: None,
                validate: Some(validate_select),
                write: None,
                branch: Some(onboarding_agent_branch),
            },
            StepDescriptor {
                id: "third-party-source",
                prompt: "Pinned third-party agent source",
                help: "Enter OWNER/REPOSITORY@COMMIT_OR_TAG:path/to/agent.md. A moving branch is not accepted.",
                help_hook: None,
                kind: StepKind::Text,
                default_answer: None,
                prefill: None,
                validate: Some(validate_third_party_source),
                write: None,
                branch: Some(|_, _| Some("third-party-warning")),
            },
            StepDescriptor {
                id: "third-party-warning",
                prompt: "Third-party agent security warning",
                help: "Third-party agent Markdown is executable policy input. It can steer tool use and delegation. Review the publisher and pinned revision before continuing.",
                help_hook: None,
                kind: StepKind::Info,
                default_answer: None,
                prefill: None,
                validate: None,
                write: None,
                branch: Some(|_, _| Some("third-party-trust-confirm")),
            },
            StepDescriptor {
                id: "third-party-trust-confirm",
                prompt: "I trust this third-party publisher and pinned revision.",
                help: "This confirmation is required separately from model trust.",
                help_hook: None,
                kind: StepKind::Confirm,
                default_answer: None,
                prefill: None,
                validate: Some(validate_required_confirmation),
                write: None,
                branch: Some(|_, _| Some("model-trust")),
            },
            StepDescriptor {
                id: "model-trust",
                prompt: "How should Cockpit classify the default model?",
                help: "Trusted models may receive unredacted content. Untrusted models keep outbound redaction enabled. Cockpit never chooses this for you.",
                help_hook: None,
                kind: StepKind::Select {
                    options: vec![
                        SelectOption {
                            id: "untrusted".into(),
                            label: "Untrusted".into(),
                            description: "Keep outbound secret redaction enabled".into(),
                        },
                        SelectOption {
                            id: "trusted".into(),
                            label: "Trusted".into(),
                            description: "Allow content without untrusted-model redaction".into(),
                        },
                    ],
                },
                default_answer: None,
                prefill: None,
                validate: Some(validate_select),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "default-model",
                prompt: "Choose this agent's default model",
                help: "Only configured models compatible with the selected agent can be installed. If you make the agent the default, this also becomes Cockpit's default model.",
                help_hook: None,
                kind: StepKind::Select {
                    // [`WizardRun::select_options`] resolves these from the
                    // preceding agent answer, including during authoritative
                    // answer replay.
                    options: Vec::new(),
                },
                default_answer: None,
                prefill: None,
                validate: Some(validate_select),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "model-trust-confirm",
                prompt: "I confirm this model trust classification.",
                help: "This confirmation is required even for the bundled agent and even when the provider already has a trust value.",
                help_hook: None,
                kind: StepKind::Confirm,
                default_answer: None,
                prefill: None,
                validate: Some(validate_required_confirmation),
                write: None,
                branch: Some(onboarding_post_model_trust_branch),
            },
            StepDescriptor {
                id: "tool-configuration",
                prompt: "Tool configuration",
                help: "Author defaults preserve the agent's native/Monty tiers. Advanced lets you enable, disable, or make tools Monty-only.",
                help_hook: None,
                kind: StepKind::Select {
                    options: vec![
                        SelectOption {
                            id: "author-defaults".into(),
                            label: "Use author tiers".into(),
                            description: "Recommended default".into(),
                        },
                        SelectOption {
                            id: "advanced".into(),
                            label: "Advanced".into(),
                            description: "Review each tool tier".into(),
                        },
                    ],
                },
                default_answer: Some(WizardAnswer::Select("author-defaults".into())),
                prefill: None,
                validate: Some(validate_select),
                write: None,
                branch: Some(onboarding_tool_configuration_branch),
            },
            StepDescriptor {
                id: "advanced-tools",
                prompt: "Set per-tool tiers",
                help: "Monty-only removes a tool from the provider-visible schema while retaining governed discovery.",
                help_hook: None,
                kind: StepKind::ToolSurface,
                default_answer: Some(WizardAnswer::ToolSurface(
                    crate::agents::ToolSurfaceSelection::default(),
                )),
                prefill: None,
                validate: None,
                write: None,
                branch: Some(|_, _| Some("monty-packages")),
            },
            StepDescriptor {
                id: "monty-packages",
                prompt: "Monty packages",
                help: "Available by default: json, csv, re, datetime, math, statistics, textwrap, base64, hashlib. The governed requests facade is per-agent and disabled by default; it becomes available only after an explicit owner-approved network-policy change, and never exposes raw sockets.",
                help_hook: None,
                kind: StepKind::Info,
                default_answer: None,
                prefill: None,
                validate: None,
                write: None,
                branch: Some(|_, _| Some("sidecar")),
            },
            StepDescriptor {
                id: "sidecar",
                prompt: "Choose an image sidecar",
                help: "Local/self-hosted vision models are preferred. Selecting a remote model requires a separate egress confirmation.",
                help_hook: None,
                kind: StepKind::Select {
                    options: sidecar_options,
                },
                default_answer: Some(sidecar_default),
                prefill: None,
                validate: Some(validate_select),
                write: None,
                branch: Some(onboarding_sidecar_branch),
            },
            StepDescriptor {
                id: "sidecar-egress-confirm",
                prompt: "I understand screenshots and image content will leave this machine.",
                help: "This is separate from model trust and is required for a cloud/unknown-location sidecar.",
                help_hook: None,
                kind: StepKind::Confirm,
                default_answer: None,
                prefill: None,
                validate: Some(validate_required_confirmation),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "make-default",
                prompt: "Make this the default agent and its selected model the default model?",
                help: "You can change either default later in Settings.",
                help_hook: None,
                kind: StepKind::Confirm,
                default_answer: Some(WizardAnswer::Confirm(true)),
                prefill: None,
                validate: None,
                write: None,
                branch: None,
            },
            action_step(
                "agent-install",
                "Install agent",
                "Installing pinned agent…",
                None,
            ),
        ],
    }
}

fn validate_required_confirmation(
    _: &WizardRun,
    answer: &WizardAnswer,
) -> std::result::Result<(), String> {
    match answer {
        WizardAnswer::Confirm(true) => Ok(()),
        _ => Err("explicit confirmation is required".into()),
    }
}

fn onboarding_agent_branch(_: &WizardRun, answer: &WizardAnswer) -> Option<&'static str> {
    matches!(answer, WizardAnswer::Select(value) if value == "third-party")
        .then_some("third-party-source")
        .or(Some("model-trust"))
}

fn validate_third_party_source(
    _: &WizardRun,
    answer: &WizardAnswer,
) -> std::result::Result<(), String> {
    let WizardAnswer::Text(locator) = answer else {
        return Err("third-party source is required".into());
    };
    let source = crate::daemon::agent_installation::CanonicalAgentSource::parse(locator)
        .map_err(|error| error.to_string())?;
    if source.owner == "FlyCockpit" && source.repository == "agents" {
        return Err("first-party agents must be selected from the catalog".into());
    }
    if source.requested_revision.is_none() {
        return Err("third-party source must pin a commit or tag".into());
    }
    Ok(())
}

fn onboarding_tool_configuration_branch(
    _: &WizardRun,
    answer: &WizardAnswer,
) -> Option<&'static str> {
    match answer {
        WizardAnswer::Select(value) if value == "advanced" => Some("advanced-tools"),
        WizardAnswer::Select(_) => Some("monty-packages"),
        _ => None,
    }
}

fn onboarding_post_model_trust_branch(_: &WizardRun, _: &WizardAnswer) -> Option<&'static str> {
    Some("tool-configuration")
}

fn onboarding_sidecar_branch(_: &WizardRun, answer: &WizardAnswer) -> Option<&'static str> {
    let WizardAnswer::Select(value) = answer else {
        return None;
    };
    if value == "disabled" {
        return Some("make-default");
    }
    if value.starts_with("local:") {
        Some("make-default")
    } else {
        Some("sidecar-egress-confirm")
    }
}

pub fn onboarding_agent_answers(
    run: &WizardRun,
    catalog_revision: String,
) -> Result<(String, crate::onboarding_agent::OnboardingAgentAnswers)> {
    use crate::onboarding_agent::{
        OnboardingAgentAnswers, OnboardingModelTrust, OnboardingSidecarSelection,
        OnboardingToolConfiguration, OnboardingToolMode,
    };
    let agent = match run.answer("agent") {
        Some(WizardAnswer::Select(value)) => value.clone(),
        _ => return Err(anyhow!("agent selection is required")),
    };
    let model_trust = match run.answer("model-trust") {
        Some(WizardAnswer::Select(value)) if value == "trusted" => OnboardingModelTrust::Trusted,
        Some(WizardAnswer::Select(value)) if value == "untrusted" => {
            OnboardingModelTrust::Untrusted
        }
        _ => return Err(anyhow!("model trust selection is required")),
    };
    let model_trust_confirmed = matches!(
        run.answer("model-trust-confirm"),
        Some(WizardAnswer::Confirm(true))
    );
    let third_party_source = (agent == "third-party")
        .then(|| match run.answer("third-party-source") {
            Some(WizardAnswer::Text(source)) => Ok(source.clone()),
            _ => Err(anyhow!("third-party source is required")),
        })
        .transpose()?;
    let third_party_trust_confirmed = !agent.eq("third-party")
        || matches!(
            run.answer("third-party-trust-confirm"),
            Some(WizardAnswer::Confirm(true))
        );
    let (default_model_provider, default_model) = match run.answer("default-model") {
        Some(WizardAnswer::Select(value)) => value
            .split_once('/')
            .map(|(provider, model)| (provider.to_string(), model.to_string()))
            .context("default model selection omitted provider or model")?,
        _ => return Err(anyhow!("default model selection is required")),
    };
    let tools = match run.answer("tool-configuration") {
        Some(WizardAnswer::Select(value)) if value == "author-defaults" => {
            OnboardingToolConfiguration::AuthorDefaults
        }
        Some(WizardAnswer::Select(value)) if value == "advanced" => {
            let selection = match run.answer("advanced-tools") {
                Some(WizardAnswer::ToolSurface(selection)) => selection,
                _ => return Err(anyhow!("advanced tool configuration is required")),
            };
            let mut modes = BTreeMap::new();
            for tool in crate::agents::known_tool_names() {
                let selected = selection.tools.iter().any(|selected| selected == tool);
                let tier = if selected {
                    Some(
                        selection
                            .tool_tiers
                            .get(*tool)
                            .copied()
                            .unwrap_or(crate::agents::ToolTier::Enabled),
                    )
                } else {
                    crate::agents::legal_tool_tiers(tool)
                        .contains(&crate::agents::ToolTier::Disabled)
                        .then_some(crate::agents::ToolTier::Disabled)
                };
                if let Some(tier) = tier {
                    modes.insert(
                        (*tool).to_string(),
                        match tier {
                            crate::agents::ToolTier::Enabled => OnboardingToolMode::Enabled,
                            crate::agents::ToolTier::Discoverable => OnboardingToolMode::MontyOnly,
                            crate::agents::ToolTier::Disabled => OnboardingToolMode::Disabled,
                        },
                    );
                }
            }
            OnboardingToolConfiguration::Advanced(modes)
        }
        _ => return Err(anyhow!("tool configuration selection is required")),
    };
    let sidecar = match run.answer("sidecar") {
        Some(WizardAnswer::Select(value)) if value == "disabled" => {
            OnboardingSidecarSelection::Disabled
        }
        Some(WizardAnswer::Select(value)) => {
            let selector = if let Some(selector) = value.strip_prefix("local:") {
                selector
            } else if let Some(selector) = value.strip_prefix("remote:") {
                selector
            } else {
                return Err(anyhow!("invalid sidecar selection"));
            };
            let (provider, model) = selector
                .split_once('/')
                .context("sidecar selection omitted provider or model")?;
            OnboardingSidecarSelection::Model {
                provider: provider.to_string(),
                model: model.to_string(),
                // Locality labels are presentation-only. The authoritative
                // resolver derives locality from the configured model; this
                // bit is exclusively the user's explicit confirmation.
                remote_image_egress_confirmed: matches!(
                    run.answer("sidecar-egress-confirm"),
                    Some(WizardAnswer::Confirm(true))
                ),
            }
        }
        _ => return Err(anyhow!("sidecar selection is required")),
    };
    Ok((
        agent,
        OnboardingAgentAnswers {
            catalog_revision,
            default_model_provider,
            default_model,
            model_trust,
            model_trust_confirmed,
            third_party_source,
            third_party_trust_confirmed,
            tools,
            sidecar,
            make_default: matches!(
                run.answer("make-default"),
                Some(WizardAnswer::Confirm(true))
            ),
        },
    ))
}

/// Extract the descriptor-bound catalog revision before a daemon reconstructs
/// the wizard. This is deliberately an opaque answer-envelope field: clients
/// never choose it, and the selected entry is still revalidated against the
/// exact pinned catalog before any side effect starts.
pub fn onboarding_catalog_revision_from_answers_json(answers_json: &str) -> Result<String> {
    let answers: BTreeMap<String, WizardAnswer> =
        serde_json::from_str(answers_json).context("deserializing wizard answers")?;
    match answers.get("__onboarding_catalog_revision") {
        Some(WizardAnswer::Text(revision))
            if revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
        {
            Ok(revision.clone())
        }
        _ => Err(anyhow!(
            "onboarding agent answers are missing the descriptor catalog revision; reopen the picker"
        )),
    }
}

pub fn onboarding_background_agents_answer(run: &WizardRun) -> Option<bool> {
    match run.answer("background-agents") {
        Some(WizardAnswer::Confirm(value)) => Some(*value),
        _ => None,
    }
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
    model_descriptor_with_selection_mode(cfg, preselect, false)
}

pub fn onboarding_model_descriptor_with_selection(
    cfg: &crate::config::providers::ProvidersConfig,
    preselect: Option<(&str, &str)>,
) -> WizardDescriptor {
    let mut descriptor = model_descriptor_with_selection_mode(cfg, preselect, true);
    descriptor.id = ONBOARDING_MODEL_WIZARD_ID;
    descriptor
}

fn model_descriptor_with_selection_mode(
    cfg: &crate::config::providers::ProvidersConfig,
    preselect: Option<(&str, &str)>,
    onboarding: bool,
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
    let mut descriptor = WizardDescriptor {
        id: MODEL_WIZARD_ID,
        title: "Configure model",
        description: "Set trust, capabilities, limits, thinking, delegation, and default model",
        write_policy: WritePolicy::CommitAtEnd,
        model_context: Some(model_context),
        onboarding_agent_models: BTreeMap::new(),
        onboarding_catalog_revision: None,
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
                prompt: if onboarding { "Model ID" } else { "Choose a model" },
                help: if onboarding { "Enter the exact provider model ID. This also works when the provider has no catalog endpoint or the catalog is unavailable." } else { "Only models configured for the selected provider are shown." },
                help_hook: None,
                kind: if onboarding { StepKind::Text } else { StepKind::Select {
                    // Resolved from the provider answer by `select_options`.
                    // Do not restore an all-provider static list here.
                    options: Vec::new(),
                } },
                default_answer: None,
                prefill: Some(if onboarding { onboarding_model_id_prefill } else { model_ref_prefill }),
                validate: Some(if onboarding { validate_onboarding_model_id } else { validate_model_ref_matches_provider }),
                write: None,
                branch: None,
            },
            StepDescriptor {
                id: "configuration",
                prompt: "Model configuration",
                help: "Smart defaults keep detected context, capabilities, modalities, compaction, and request-wire settings. Open Advanced only when you need an override.",
                help_hook: None,
                kind: StepKind::Select {
                    options: vec![
                        SelectOption {
                            id: "smart-defaults".into(),
                            label: "Use smart defaults".into(),
                            description: "Recommended; keep detected provider and model behavior".into(),
                        },
                        SelectOption {
                            id: "advanced".into(),
                            label: "Advanced".into(),
                            description: "Review trust, capabilities, context, thinking, and delegation".into(),
                        },
                    ],
                },
                default_answer: Some(WizardAnswer::Select("smart-defaults".to_string())),
                prefill: None,
                validate: Some(validate_select),
                write: None,
                branch: Some(model_configuration_branch),
            },
            StepDescriptor {
                id: "trust",
                prompt: "Provider trust (data custody)",
                help: "Capture policy only, independent of locality. All inference requests use reference-only redaction for sealed values. trusted: may participate in host-mediated secret capture; untrusted: cannot capture secrets. Exports and client display stay redacted either way. Provider default is shown by inheritance.",
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
                                "Permit host-mediated secret capture; inference requests remain reference-only"
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
    };
    if !onboarding {
        descriptor.steps.retain(|step| step.id != "configuration");
    }
    descriptor
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

    let mut ordered_templates = TEMPLATES.iter().collect::<Vec<_>>();
    ordered_templates.sort_by_key(|template| match template.id {
        "codex-oauth" | "copilot" | "grok-oauth" => 0,
        _ => 1,
    });
    let template_options = ordered_templates
        .into_iter()
        .map(|template| SelectOption {
            id: template.id.into(),
            label: template.display_label(),
            description: template
                .disabled_reason()
                .or(template.display_hint())
                .unwrap_or("Provider template")
                .into(),
        })
        .collect();
    WizardDescriptor {
        id: PROVIDER_WIZARD_ID,
        title: "Add provider",
        description: "Configure an inference provider and its authentication",
        write_policy: WritePolicy::PerStep,
        model_context: None,
        onboarding_agent_models: BTreeMap::new(),
        onboarding_catalog_revision: None,
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
                validate: Some(validate_provider_template),
                write: None,
                branch: Some(provider_template_branch),
            },
            StepDescriptor {
                id: ProviderWizardStep::WireApi.source_id(),
                prompt: "Choose request wire",
                help: "Choose the API shape your endpoint accepts. Auto keeps Cockpit's normal endpoint detection and fallback behavior.",
                help_hook: None,
                kind: StepKind::Select {
                    options: vec![
                        SelectOption {
                            id: "auto".into(),
                            label: "Auto".into(),
                            description: "Let Cockpit select the request wire".into(),
                        },
                        SelectOption {
                            id: "completions".into(),
                            label: "Chat Completions".into(),
                            description: "Use the OpenAI-compatible /chat/completions API".into(),
                        },
                        SelectOption {
                            id: "responses".into(),
                            label: "Responses".into(),
                            description: "Use the OpenAI Responses API".into(),
                        },
                        SelectOption {
                            id: "anthropic".into(),
                            label: "Anthropic".into(),
                            description: "Use Anthropic's native Messages API".into(),
                        },
                    ],
                },
                default_answer: Some(WizardAnswer::Select("auto".to_string())),
                prefill: None,
                validate: Some(validate_provider_wire_api),
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
                Some(action_to_saving),
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
                        SelectOption {
                            id: "copy-detected-env".into(),
                            label: "Copy detected value".into(),
                            description:
                                "Copy a detected shell value into Cockpit's encrypted vault".into(),
                        },
                    ],
                },
                default_answer: Some(WizardAnswer::Select("paste-key".to_string())),
                prefill: Some(provider_auth_method_prefill),
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
                Some(action_to_saving),
            ),
            action_step(
                ProviderWizardStep::GrokOAuth.source_id(),
                "Sign in to Grok",
                "Waiting for browser authorization…",
                Some(action_to_saving),
            ),
            action_step(
                ProviderWizardStep::CodexOAuth.source_id(),
                "Sign in to Codex",
                "Waiting for device authorization…",
                Some(action_to_saving),
            ),
            action_step(
                ProviderWizardStep::CopyDetectedEnv.source_id(),
                "Copy detected environment credential",
                "Copying detected credential into Cockpit's encrypted vault…",
                Some(action_to_saving),
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
            action_step(
                ProviderWizardStep::TestKey.source_id(),
                "Test key",
                "Testing provider credentials…",
                Some(fetching_to_done),
            ),
            action_step(
                ProviderWizardStep::Fetching.source_id(),
                "Fetch models",
                "Fetching /models…",
                Some(fetching_to_done),
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
        onboarding_agent_models: BTreeMap::new(),
        onboarding_catalog_revision: None,
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
    match run.answer("model")? {
        WizardAnswer::Select(value) => {
            let (provider, model) = value.split_once(':')?;
            Some((provider.to_string(), model.to_string()))
        }
        WizardAnswer::Text(model) => Some((model_provider_answer(run)?, model.trim().to_string())),
        _ => None,
    }
}

fn onboarding_model_id_prefill(run: &WizardRun) -> Option<WizardAnswer> {
    let WizardAnswer::Select(value) = model_ref_prefill(run)? else {
        return None;
    };
    let (_, model) = value.split_once(':')?;
    Some(WizardAnswer::Text(model.to_string()))
}

fn validate_onboarding_model_id(
    _: &WizardRun,
    answer: &WizardAnswer,
) -> std::result::Result<(), String> {
    match answer {
        WizardAnswer::Text(value) if !value.trim().is_empty() && !value.contains(':') => Ok(()),
        WizardAnswer::Text(_) => {
            Err("enter a non-empty model ID without a provider prefix".to_string())
        }
        _ => Err("model ID must be text".to_string()),
    }
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
    if matches!(
        run.answer("configuration"),
        Some(WizardAnswer::Select(value)) if value == "smart-defaults"
    ) {
        return true;
    }
    matches!(
        run.answer("default-model"),
        Some(WizardAnswer::Confirm(true))
    )
}

pub fn onboarding_name_answer(run: &WizardRun) -> Option<String> {
    let WizardAnswer::Text(value) = run.answer("name")? else {
        return None;
    };
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
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

/// Shared action-step constructor. Provider-wizard actions pass an explicit
/// branch (`saving` or `done`). Terminal save actions (`profile-save`,
/// `security-save`, `model-save`, `lifetime-save`, `agent-install`) must pass
/// `None` so they finish the wizard instead of branching into the provider
/// `saving` step.
fn action_step(
    id: &'static str,
    prompt: &'static str,
    progress: &'static str,
    branch: Option<BranchHook>,
) -> StepDescriptor {
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
        branch,
    }
}

fn validate_select(_: &WizardRun, answer: &WizardAnswer) -> std::result::Result<(), String> {
    match answer {
        WizardAnswer::Select(value) if !value.is_empty() => Ok(()),
        _ => Err("choose one option".to_string()),
    }
}

fn onboarding_name_prefill(_: &WizardRun) -> Option<WizardAnswer> {
    ["USER", "USERNAME"]
        .into_iter()
        .find_map(|name| std::env::var(name).ok())
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .map(WizardAnswer::Text)
}

fn validate_onboarding_name(
    _: &WizardRun,
    answer: &WizardAnswer,
) -> std::result::Result<(), String> {
    let WizardAnswer::Text(value) = answer else {
        return Err("enter a name or leave it blank to skip".to_string());
    };
    if value.chars().count() > 80 {
        return Err("name must be 80 characters or fewer".to_string());
    }
    if value.chars().any(char::is_control) {
        return Err("name cannot contain control characters".to_string());
    }
    Ok(())
}

fn validate_provider_template(
    _: &WizardRun,
    answer: &WizardAnswer,
) -> std::result::Result<(), String> {
    let WizardAnswer::Select(id) = answer else {
        return Err("choose an option".to_string());
    };
    if id.is_empty() {
        return Err("choose an option".to_string());
    }
    let Some(template) = crate::providers::template_by_id(id) else {
        return Err("choose a listed provider template".to_string());
    };
    match template.disabled_reason() {
        Some(reason) => Err(reason.to_string()),
        None => Ok(()),
    }
}

fn validate_provider_wire_api(
    _: &WizardRun,
    answer: &WizardAnswer,
) -> std::result::Result<(), String> {
    let WizardAnswer::Select(value) = answer else {
        return Err("choose auto, completions, responses, or anthropic".to_string());
    };
    provider_wire_api_from_id(value)
        .map(|_| ())
        .ok_or_else(|| "choose auto, completions, responses, or anthropic".to_string())
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
    let wire_api = provider_wire_api_for_template(run, template);
    provider_entry_for_template_with_wire_api(
        template,
        provider_url_answer(run)?,
        headers,
        wire_api,
    )
    .into()
}

fn provider_wire_api_answer(run: &WizardRun) -> Option<crate::config::providers::WireApi> {
    let WizardAnswer::Select(value) = run.answer(ProviderWizardStep::WireApi.source_id())? else {
        return None;
    };
    provider_wire_api_from_id(value)
}

/// Resolve the wire for a template from this run's answers.
///
/// A wire-picker answer is authoritative only for templates that expose that
/// picker. `WizardRun::back` deliberately retains answers, so an answer from a
/// previously selected custom template must not override a pinned template.
pub fn provider_wire_api_for_template(
    run: &WizardRun,
    template: &crate::providers::ProviderTemplate,
) -> crate::config::providers::WireApi {
    if provider_template_exposes_wire_api_picker(template) {
        provider_wire_api_answer(run).unwrap_or(template.default_wire_api)
    } else {
        template.default_wire_api
    }
}

pub fn provider_entry_for_template(
    template: &'static crate::providers::ProviderTemplate,
    url: String,
    headers: Vec<crate::config::providers::HeaderSpec>,
) -> crate::config::providers::ProviderEntry {
    provider_entry_for_template_with_wire_api(template, url, headers, template.default_wire_api)
}

pub fn provider_entry_for_template_with_wire_api(
    template: &'static crate::providers::ProviderTemplate,
    url: String,
    headers: Vec<crate::config::providers::HeaderSpec>,
    wire_api: crate::config::providers::WireApi,
) -> crate::config::providers::ProviderEntry {
    use crate::auth::codex_oauth;
    use crate::config::providers::{
        AnthropicFeatures, AuthKind, ProviderEntry, ProviderModelCatalog,
    };

    #[cfg(feature = "grok-subscription")]
    let is_grok_oauth = template.id == crate::auth::xai_oauth::CREDENTIAL_KEY;
    #[cfg(not(feature = "grok-subscription"))]
    let is_grok_oauth = false;
    let auth = if is_grok_oauth || template.id == codex_oauth::CREDENTIAL_KEY {
        Some(AuthKind::OAuth)
    } else {
        Some(template.auth)
    };
    let credential_ref = if is_grok_oauth {
        Some("grok-oauth".to_string())
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
        auth_command: None,
        oauth: None,
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
        anthropic: (template.id == "anthropic").then(AnthropicFeatures::first_party),
        shrink: Default::default(),
        context: Default::default(),
        auto_prune: None,
        timeout: Default::default(),
        wire_api,
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

/// Prefer a reference when this onboarding process can see one of the
/// template's declared credential variables. The daemon still proves that it
/// can resolve the reference during the mandatory live check; detection here
/// never reads or copies the credential bytes.
fn provider_auth_method_prefill(run: &WizardRun) -> Option<WizardAnswer> {
    let template = selected_provider_template(run)?;
    crate::providers::detected_env_var(template)
        .map(|_| WizardAnswer::Select("env-var".to_string()))
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
        "provider default: {} · capture policy only, independent of locality · all inference requests use reference-only redaction for sealed values · trusted: host-mediated capture capable · untrusted: capture disabled · exports and client display stay redacted either way.",
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

fn model_configuration_branch(_: &WizardRun, answer: &WizardAnswer) -> Option<&'static str> {
    Some(match answer {
        WizardAnswer::Select(value) if value == "advanced" => "trust",
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

fn provider_template_branch(run: &WizardRun, _: &WizardAnswer) -> Option<&'static str> {
    let template = selected_provider_template(run)?;
    Some(if provider_template_exposes_wire_api_picker(template) {
        ProviderWizardStep::WireApi.source_id()
    } else {
        ProviderWizardStep::ProviderId.source_id()
    })
}

fn provider_template_exposes_wire_api_picker(
    template: &crate::providers::ProviderTemplate,
) -> bool {
    template.id == "openai-compatible" || template.default_wire_api.is_auto()
}

fn provider_wire_api_from_id(value: &str) -> Option<crate::config::providers::WireApi> {
    use crate::config::providers::WireApi;

    Some(match value {
        "auto" => WireApi::Auto,
        "completions" => WireApi::Completions,
        "responses" => WireApi::Responses,
        "anthropic" => WireApi::Anthropic,
        _ => return None,
    })
}

fn provider_auth_method_branch(_: &WizardRun, answer: &WizardAnswer) -> Option<&'static str> {
    Some(match answer {
        WizardAnswer::Select(value) if value == "paste-key" => "api-key",
        WizardAnswer::Select(value) if value == "env-var" => "env-var",
        WizardAnswer::Select(value) if value == "advanced-headers" => "headers",
        WizardAnswer::Select(value) if value == "copy-detected-env" => "copy-detected-env",
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
        "test-key"
    } else if selected_provider_template(run)?.supports_models_endpoint {
        "fetching"
    } else {
        "done"
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn api_key_provider_setup_enters_live_validation_without_a_skip_branch() {
        let mut run = WizardRun::new(provider_descriptor_with_template(Some("openai"))).unwrap();
        run.submit(WizardAnswer::Select("openai".into())).unwrap();
        run.return_to(ProviderWizardStep::Saving.source_id())
            .unwrap();
        run.submit(WizardAnswer::Acknowledged).unwrap();

        assert_eq!(
            run.current_step_id(),
            Some(ProviderWizardStep::TestKey.source_id()),
            "saving an API-key provider must enter live credential validation"
        );
        assert!(
            !ProviderWizardStep::ALL
                .iter()
                .any(|step| step.source_id().contains("skip")),
            "the provider wizard must not expose an unvalidated completion branch"
        );
    }

    #[test]
    fn onboarding_profile_save_completes_without_a_saving_branch() {
        let mut run = WizardRun::new(onboarding_profile_descriptor()).unwrap();
        run.submit(WizardAnswer::Text("Ada".into())).unwrap();
        assert_eq!(run.current_step_id(), Some("profile-save"));
        run.submit(WizardAnswer::Acknowledged)
            .expect("profile-save is a terminal action, not a branch to `saving`");
        assert!(run.is_complete());
        assert_eq!(onboarding_name_answer(&run), Some("Ada".into()));
    }

    #[test]
    fn onboarding_profile_blank_name_is_a_skip_that_still_completes() {
        let mut run = WizardRun::new(onboarding_profile_descriptor()).unwrap();
        run.submit(WizardAnswer::Text(String::new())).unwrap();
        assert_eq!(run.current_step_id(), Some("profile-save"));
        run.submit(WizardAnswer::Acknowledged)
            .expect("skipping the name still completes profile-save");
        assert!(run.is_complete());
        assert_eq!(onboarding_name_answer(&run), None);
    }

    #[test]
    fn onboarding_model_wizard_accepts_manual_model_id_and_context() {
        let mut providers = crate::config::providers::ProvidersConfig::default();
        providers.providers.insert(
            "openai".into(),
            crate::config::providers::ProviderEntry::default(),
        );
        let descriptor = onboarding_model_descriptor_with_selection(&providers, None);
        let model = descriptor
            .steps
            .iter()
            .find(|step| step.id == "model")
            .unwrap();
        assert!(matches!(model.kind, StepKind::Text));
        assert!(
            descriptor
                .steps
                .iter()
                .any(|step| step.id == "context-tokens")
        );

        let mut run = WizardRun::new(descriptor).unwrap();
        run.submit(WizardAnswer::Select("openai".into())).unwrap();
        run.submit(WizardAnswer::Text("manual-model-id".into()))
            .unwrap();
        assert_eq!(
            model_ref_answer(&run),
            Some(("openai".into(), "manual-model-id".into()))
        );
    }

    #[test]
    fn interrupted_onboarding_wizard_resumes_after_last_accepted_answer() {
        let descriptor = onboarding_profile_descriptor();
        let mut run = WizardRun::new(descriptor.clone()).unwrap();
        run.submit(WizardAnswer::Text("Ada".into())).unwrap();

        let resumed =
            WizardRun::resume_from_answers_json(descriptor, &run.answers_json().unwrap()).unwrap();

        assert_eq!(resumed.current_step_id(), Some("profile-save"));
        assert_eq!(
            resumed.answer("name"),
            Some(&WizardAnswer::Text("Ada".into()))
        );
    }

    #[test]
    fn onboarding_lifetime_requires_explicit_persistent_or_ephemeral_choice() {
        let mut run = WizardRun::new(onboarding_lifetime_descriptor()).unwrap();
        assert_eq!(run.current_step_id(), Some("background-agents"));
        assert_eq!(run.prefill(), Some(WizardAnswer::Confirm(true)));

        run.submit(WizardAnswer::Confirm(false)).unwrap();

        assert_eq!(run.current_step_id(), Some("lifetime-save"));
        assert_eq!(onboarding_background_agents_answer(&run), Some(false));
    }

    /// Terminal profile-save must finish the wizard. Branching to a
    /// provider-wizard `saving` step is a hard submit error and stalls
    /// first-run at AwaitProfile.
    #[test]
    fn onboarding_profile_save_completes_without_saving_step() {
        let mut live = WizardRun::new(onboarding_profile_descriptor()).unwrap();
        live.submit(WizardAnswer::Text("Ada".into())).unwrap();
        assert_eq!(live.current_step_id(), Some("profile-save"));
        live.submit(WizardAnswer::Acknowledged)
            .expect("profile-save is a terminal action");
        assert!(live.is_complete());
        assert_eq!(onboarding_name_answer(&live).as_deref(), Some("Ada"));

        let mut client = WizardRun::new(onboarding_profile_descriptor()).unwrap();
        client.submit(WizardAnswer::Text("Ada".into())).unwrap();
        let json = client.answers_json().unwrap();
        assert!(
            !json.contains("profile-save"),
            "the client acknowledges the save only after the daemon reply: {json}"
        );

        let reconstructed = WizardRun::from_answers_json(onboarding_profile_descriptor(), &json)
            .expect("daemon reconstruction infers the terminal save acknowledgement");
        assert!(reconstructed.is_complete());
        assert_eq!(
            onboarding_name_answer(&reconstructed).as_deref(),
            Some("Ada")
        );
    }

    /// Terminal lifetime-save must finish the wizard the same way profile-save
    /// does: the client omits the action from answers_json, and daemon replay
    /// infers the acknowledgement.
    #[test]
    fn onboarding_lifetime_save_completes_without_a_saving_step() {
        let mut live = WizardRun::new(onboarding_lifetime_descriptor()).unwrap();
        live.submit(WizardAnswer::Confirm(false)).unwrap();
        assert_eq!(live.current_step_id(), Some("lifetime-save"));
        live.submit(WizardAnswer::Acknowledged)
            .expect("lifetime-save is a terminal action");
        assert!(live.is_complete());
        assert_eq!(onboarding_background_agents_answer(&live), Some(false));

        let mut client = WizardRun::new(onboarding_lifetime_descriptor()).unwrap();
        client.submit(WizardAnswer::Confirm(false)).unwrap();
        let json = client.answers_json().unwrap();
        assert!(
            !json.contains("lifetime-save"),
            "the client acknowledges the save only after the daemon reply: {json}"
        );

        let reconstructed = WizardRun::from_answers_json(onboarding_lifetime_descriptor(), &json)
            .expect("daemon reconstruction infers the terminal save acknowledgement");
        assert!(reconstructed.is_complete());
        assert_eq!(
            onboarding_background_agents_answer(&reconstructed),
            Some(false)
        );
    }

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

    /// The model wizard must present capture policy as its own decision and
    /// never suggest that locality implies trust.
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
                .contains("Capture policy only, independent of locality"),
            "trust help: {}",
            trust.help
        );
        assert!(
            trust
                .help
                .contains("All inference requests use reference-only redaction"),
            "trust help: {}",
            trust.help
        );
        assert!(
            trust
                .help
                .contains("trusted: may participate in host-mediated secret capture"),
            "trust help must state the capture capability: {}",
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
            trusted.description.contains("capture"),
            "trusted option must state the capture effect: {}",
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
            onboarding_agent_models: BTreeMap::new(),
            onboarding_catalog_revision: None,
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
            onboarding_agent_models: BTreeMap::new(),
            onboarding_catalog_revision: None,
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
    fn provider_wizard_offers_detected_environment_copy_before_saving() {
        let descriptor = provider_descriptor_with_template(Some("openai"));
        let auth = descriptor
            .steps
            .iter()
            .find(|step| step.id == "auth-method")
            .expect("auth method step");
        let StepKind::Select { options } = &auth.kind else {
            panic!("auth method must be a select")
        };
        assert!(options.iter().any(|option| option.id == "env-var"));
        assert!(
            options
                .iter()
                .any(|option| option.id == "copy-detected-env")
        );

        let mut run = WizardRun::new(descriptor).unwrap();
        run.submit(WizardAnswer::Select("openai".into())).unwrap();
        run.submit(WizardAnswer::Text("openai".into())).unwrap();
        run.submit(WizardAnswer::Text("https://api.openai.com/v1".into()))
            .unwrap();
        run.submit(WizardAnswer::Select("copy-detected-env".into()))
            .unwrap();
        assert_eq!(run.current_step_id(), Some("copy-detected-env"));
        run.submit(WizardAnswer::Acknowledged).unwrap();
        assert_eq!(run.current_step_id(), Some("saving"));
    }

    #[cfg(not(feature = "grok-subscription"))]
    #[test]
    fn provider_wizard_shows_and_rejects_the_disabled_grok_template() {
        let descriptor = provider_descriptor();
        let template_step = descriptor
            .steps
            .iter()
            .find(|step| step.id == "template")
            .expect("template step");
        let StepKind::Select { options } = &template_step.kind else {
            panic!("template step must be a select")
        };
        let grok = options
            .iter()
            .find(|option| option.id == "grok-oauth")
            .expect("disabled Grok entry remains visible");
        assert!(grok.label.contains("disabled pending xAI authorization"));
        assert!(grok.description.contains("auth_command"));

        let mut run = WizardRun::new(descriptor).unwrap();
        let error = run
            .submit(WizardAnswer::Select("grok-oauth".to_string()))
            .unwrap_err();
        assert!(error.contains("disabled pending xAI authorization"));
    }

    fn custom_provider_entry_for_wire(wire: &str) -> crate::config::providers::ProviderEntry {
        let mut run = WizardRun::new(provider_descriptor()).unwrap();
        run.submit(WizardAnswer::Select("openai-compatible".to_string()))
            .unwrap();
        assert_eq!(run.current_step_id(), Some("wire-api"));
        run.submit(WizardAnswer::Select(wire.to_string())).unwrap();
        run.submit(WizardAnswer::Text("custom".to_string()))
            .unwrap();
        run.submit(WizardAnswer::Text("https://example.test/v1".to_string()))
            .unwrap();
        provider_entry_from_answers(&run, Vec::new()).expect("custom provider entry")
    }

    #[test]
    fn custom_provider_wire_picker_materializes_selected_wire() {
        use crate::config::providers::WireApi;

        for (selection, expected) in [
            ("completions", WireApi::Completions),
            ("responses", WireApi::Responses),
            ("anthropic", WireApi::Anthropic),
        ] {
            let entry = custom_provider_entry_for_wire(selection);
            assert_eq!(entry.wire_api, expected, "selection {selection}");
            assert!(
                entry.effective_anthropic_features().is_empty(),
                "custom provider `{selection}` must not enable Anthropic extensions"
            );
        }
    }

    #[test]
    fn custom_provider_wire_picker_defaults_to_auto() {
        use crate::config::providers::WireApi;

        let mut run = WizardRun::new(provider_descriptor()).unwrap();
        run.submit(WizardAnswer::Select("openai-compatible".to_string()))
            .unwrap();
        assert_eq!(
            run.prefill(),
            Some(WizardAnswer::Select("auto".to_string()))
        );
        run.submit(run.prefill().expect("wire picker default"))
            .unwrap();
        run.submit(WizardAnswer::Text("custom".to_string()))
            .unwrap();
        run.submit(WizardAnswer::Text("https://example.test/v1".to_string()))
            .unwrap();
        assert_eq!(
            provider_entry_from_answers(&run, Vec::new())
                .expect("custom provider entry")
                .wire_api,
            WireApi::Auto
        );
    }

    #[test]
    fn pinned_provider_templates_skip_wire_picker_and_keep_their_wire() {
        use crate::config::providers::WireApi;

        let mut run = WizardRun::new(provider_descriptor_with_template(Some("anthropic"))).unwrap();
        run.submit(WizardAnswer::Select("anthropic".to_string()))
            .unwrap();
        assert_eq!(run.current_step_id(), Some("id"));
        run.submit(WizardAnswer::Text("anthropic".to_string()))
            .unwrap();
        run.submit(WizardAnswer::Text(
            "https://api.anthropic.com/v1".to_string(),
        ))
        .unwrap();
        let entry =
            provider_entry_from_answers(&run, Vec::new()).expect("Anthropic provider entry");
        assert_eq!(entry.wire_api, WireApi::Anthropic);
        assert_eq!(
            entry.anthropic,
            Some(crate::config::providers::AnthropicFeatures::first_party())
        );
    }

    #[test]
    fn pinned_provider_template_ignores_retained_custom_wire_answer_after_backtracking() {
        use crate::config::providers::WireApi;

        let mut run = WizardRun::new(provider_descriptor()).unwrap();
        run.submit(WizardAnswer::Select("openai-compatible".to_string()))
            .unwrap();
        run.submit(WizardAnswer::Select("responses".to_string()))
            .unwrap();
        assert_eq!(run.current_step_id(), Some("id"));
        assert!(run.back());
        assert!(run.back());
        assert_eq!(run.current_step_id(), Some("template"));

        run.submit(WizardAnswer::Select("anthropic".to_string()))
            .unwrap();
        assert_eq!(run.current_step_id(), Some("id"));
        run.submit(WizardAnswer::Text("anthropic".to_string()))
            .unwrap();
        run.submit(WizardAnswer::Text(
            "https://api.anthropic.com/v1".to_string(),
        ))
        .unwrap();

        assert_eq!(
            provider_entry_from_answers(&run, Vec::new())
                .expect("Anthropic provider entry")
                .wire_api,
            WireApi::Anthropic
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
