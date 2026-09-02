//! Config writers behind the security and model setup wizards.
//!
//! [`WizardRun`] in the parent module is pure: it validates answers and
//! tracks navigation but never touches disk. These functions are the other
//! half — they resolve which config layer is writable for a `cwd`, diff the
//! collected answers against the effective config, and persist only what
//! actually changed.
//!
//! They live in `cockpit-core` rather than in a front end because every
//! surface that can run a wizard must write identical config. These are the
//! approval/sandbox/redaction and model-trust/delegation chokepoints
//! (`sandbox.default_mode`, `default_approval_mode`,
//! `redact.min_secret_length`, model `trust`/`can_delegate`/capability
//! overrides), so a second copy is a security divergence, not just
//! duplication. `cockpit setup` (terminal renderer) and the TUI settings
//! pane both call in here.
//!
//! Inheritance rule shared by every writer below: an answer equal to the
//! currently-resolved value leaves the existing override untouched; an
//! answer equal to the inherited/base value clears the override; anything
//! else writes an explicit override.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::config::dirs::global_config_file;
use crate::config::extended::ExtendedConfigDoc;
use crate::config::providers::ConfigDoc;
use crate::wizard::{
    WizardDescriptor, WizardRun, approval_mode_answer, min_secret_length_answer,
    model_capability_answers, model_context_tokens_answer, model_default_thinking_answer,
    model_make_default_answer, model_max_output_tokens_answer, model_ref_answer,
    model_subagent_answers, model_system_prompt_answer, model_trust_answer, sandbox_mode_answer,
};

pub struct PreparedOnboardingAgent {
    pub plan: crate::onboarding_agent::OnboardingAgentPlan,
    pub providers: crate::config::providers::ProvidersConfig,
}

/// Exact pre-onboarding bytes for the configuration files this flow owns.
/// The daemon holds the config-publication boundary while this token is live;
/// it is therefore safe to compensate a later database/install failure without
/// overwriting an interleaved daemon publisher.
#[derive(Clone, Serialize, Deserialize)]
pub struct OnboardingConfigRollback {
    files: Vec<(PathBuf, Option<Vec<u8>>)>,
}

impl OnboardingConfigRollback {
    fn capture(paths: impl IntoIterator<Item = PathBuf>) -> Result<Self> {
        let files = paths
            .into_iter()
            .map(|path| {
                let bytes = match std::fs::read(&path) {
                    Ok(bytes) => Some(bytes),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => {
                        return Err(anyhow!(error))
                            .with_context(|| format!("capturing {}", path.display()));
                    }
                };
                Ok((path, bytes))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { files })
    }

    pub fn restore(self) -> Result<()> {
        for (path, bytes) in self.files {
            match bytes {
                Some(bytes) => crate::config::config::files::atomic_write(&path, &bytes)
                    .with_context(|| format!("restoring {}", path.display()))?,
                None => match std::fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(anyhow!(error)).with_context(|| {
                            format!("removing {} during rollback", path.display())
                        });
                    }
                },
            }
        }
        Ok(())
    }

    /// Persist exact pre-publication bytes in daemon-private state before the
    /// installation operation starts. SQLite records only this path and the
    /// operation identity, never config contents (which can contain refs).
    pub fn write_durable_journal(&self, operation_id: uuid::Uuid) -> Result<PathBuf> {
        let root = cockpit_config::config::resolve::cockpit_state_dir()
            .context("resolving daemon state directory for onboarding journal")?
            .join("onboarding-agent-publication");
        cockpit_host::private_fs::ensure_private_dir(&root)
            .context("securing onboarding publication journal directory")?;
        let path = root.join(format!("{operation_id}.json"));
        let bytes = serde_json::to_vec(self).context("serializing onboarding config journal")?;
        crate::config::config::files::atomic_write(&path, &bytes)
            .with_context(|| format!("writing onboarding config journal {}", path.display()))?;
        cockpit_host::private_fs::repair_private_file(&path, "onboarding config journal")
            .context("securing onboarding config journal")?;
        Ok(path)
    }

    pub fn restore_durable_journal(path: &Path) -> Result<()> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading onboarding config journal {}", path.display()))?;
        let journal: Self =
            serde_json::from_slice(&bytes).context("decoding onboarding config journal")?;
        journal.restore()
    }

    pub fn discard_durable_journal(path: &Path) -> Result<()> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(anyhow!(error))
                .with_context(|| format!("removing onboarding config journal {}", path.display())),
        }
    }
}

/// Capture exactly the files that onboarding can publish. This must happen
/// before installation begins so a process death can always reconcile to
/// either the complete plan or the previous durable state.
pub fn capture_onboarding_agent_config(
    plan: &crate::onboarding_agent::OnboardingAgentPlan,
) -> Result<OnboardingConfigRollback> {
    let global_config = global_config_file().context("resolving global agent onboarding config")?;
    let model_target = crate::config::providers::provider_file_path_for_config(
        &global_config,
        &plan.default_model.provider,
    )
    .context("resolving onboarding model config")?;
    OnboardingConfigRollback::capture([global_config, model_target])
}

pub async fn prepare_onboarding_agent_answers(
    answers_json: &str,
) -> Result<PreparedOnboardingAgent> {
    let revision = crate::wizard::onboarding_catalog_revision_from_answers_json(answers_json)?;
    let catalog = if revision == crate::daemon::agent_catalog::BUNDLED_CATALOG_REVISION {
        crate::daemon::agent_catalog::ResolvedAgentCatalog {
            revision,
            origin: crate::daemon::agent_catalog::AgentCatalogOrigin::Cached,
            index: crate::daemon::agent_catalog::cached_catalog()?,
        }
    } else {
        crate::daemon::agent_catalog::fetch_catalog_at_revision(&revision).await?
    };
    prepare_onboarding_agent_answers_for_catalog(answers_json, catalog)
}

/// Bind onboarding answers to one already-resolved catalog.  The daemon uses
/// this form to perform network discovery before taking the publication lock;
/// all config reads and writes then share that one serialized boundary.
pub fn prepare_onboarding_agent_answers_for_catalog(
    answers_json: &str,
    catalog: crate::daemon::agent_catalog::ResolvedAgentCatalog,
) -> Result<PreparedOnboardingAgent> {
    let global_config = global_config_file().context("resolving global agent onboarding config")?;
    let providers = ConfigDoc::load(&global_config)?.providers();
    // Discovery is part of the selection authority, not an install-time
    // afterthought.  Reuse this exact resolved catalog for descriptor replay
    // and the eventual pinned lookup so live-only agents remain selectable.
    let descriptor = crate::wizard::onboarding_agent_descriptor(
        &providers,
        &catalog.index,
        catalog.revision.clone(),
    );
    let run = WizardRun::from_answers_json(descriptor, answers_json)?;
    let (slug, answers) = crate::wizard::onboarding_agent_answers(&run, catalog.revision.clone())?;
    let entry = (slug != "third-party")
        .then(|| catalog.index.entry(&slug))
        .flatten();
    let plan = crate::onboarding_agent::build_onboarding_agent_plan(entry, answers, &providers)?;
    Ok(PreparedOnboardingAgent { plan, providers })
}

pub fn persist_onboarding_agent_plan(
    plan: &crate::onboarding_agent::OnboardingAgentPlan,
) -> Result<OnboardingConfigRollback> {
    let global_config = global_config_file().context("resolving global agent onboarding config")?;
    let model_target = crate::config::providers::provider_file_path_for_config(
        &global_config,
        &plan.default_model.provider,
    )
    .context("resolving onboarding model config")?;
    let rollback =
        OnboardingConfigRollback::capture([global_config.clone(), model_target.clone()])?;
    let result = (|| {
        let mut model_doc = ConfigDoc::load(&model_target)?;
        let mut model_layer = model_doc.providers();
        let provider = model_layer
            .providers
            .entry(plan.default_model.provider.clone())
            .or_default();
        let model_index = provider
            .models
            .iter()
            .position(|model| model.id == plan.default_model.model)
            .unwrap_or_else(|| {
                provider.models.push(crate::config::providers::ModelEntry {
                    id: plan.default_model.model.clone(),
                    ..Default::default()
                });
                provider.models.len() - 1
            });
        let model = provider
            .models
            .get_mut(model_index)
            .context("onboarding model insertion failed")?;
        model.trust = Some(plan.model_trust);
        model_doc.write_model_wizard_fields(&plan.default_model.provider, model)?;

        if plan.make_default {
            crate::config::providers::mutate_effective_default(
                global_config
                    .parent()
                    .context("global config file has no parent directory")?,
                Some(&plan.default_model),
                crate::config::providers::ActiveModelWriteMode::Replace,
                None,
                None,
                None,
            )
            .map_err(|error| anyhow!("{}", error.user_message))?;
        }

        let mut extended_doc = ExtendedConfigDoc::load(&global_config)?;
        let mut extended = extended_doc.config();
        let mut providers = ConfigDoc::load(&global_config)?.providers();
        plan.apply_to_configs(&mut providers, &mut extended)?;
        extended_doc.write(&extended)?;
        Ok(())
    })();
    match result {
        Ok(()) => Ok(rollback),
        Err(error) => {
            rollback
                .restore()
                .context("rolling back failed onboarding config publication")?;
            Err(error)
        }
    }
}

/// Compose a daemon-less host-capability snapshot for the setup wizard.
/// Callers inject this; the wizard never consults a process-global cache.
pub async fn compose_wizard_host_capabilities(cwd: &Path) -> cockpit_proto::HostCapabilitySnapshot {
    let probes = crate::host_capabilities::HostCapabilityProbeInputs::production(cwd.to_path_buf());
    let collected = crate::host_capabilities::collect_shared_host_probes(&probes, false).await;
    crate::host_capabilities::build_host_capability_snapshot(
        1,
        &collected,
        cockpit_proto::SecretStoreSnapshot::unconfigured_placeholder(),
    )
}

/// Build the descriptor for wizard `id`. Security and model onboarding are
/// seeded exclusively from the canonical global layer: workspace trust and
/// workspace overlays must not influence a user-global choice. Every other
/// wizard is static and comes straight from the registry.
pub fn descriptor_for_cwd(id: &str, cwd: &Path) -> Option<WizardDescriptor> {
    descriptor_for_cwd_with_caps(id, cwd, None)
}

/// Like [`descriptor_for_cwd`], but the security wizard takes an injected
/// [`cockpit_proto::HostCapabilitySnapshot`]. Missing snapshot is fail-closed
/// (no host On, no container rows).
pub fn descriptor_for_cwd_with_caps(
    id: &str,
    _cwd: &Path,
    caps: Option<&cockpit_proto::HostCapabilitySnapshot>,
) -> Option<WizardDescriptor> {
    let global_config = global_config_file().ok()?;
    if id == crate::wizard::SECURITY_WIZARD_ID {
        let current = ExtendedConfigDoc::load(&global_config)
            .ok()
            .map(|doc| doc.config())
            .unwrap_or_default();
        let unpublished = crate::daemon::session_worker::unpublished_host_capability_snapshot();
        let caps = caps.unwrap_or(&unpublished);
        return Some(crate::wizard::security_descriptor_for_config_with_caps(
            &current, caps,
        ));
    }
    if id == crate::wizard::MODEL_WIZARD_ID {
        let current = ConfigDoc::load(&global_config)
            .ok()
            .map(|doc| doc.providers())
            .unwrap_or_default();
        return Some(crate::wizard::model_descriptor_with_selection(
            &current, None,
        ));
    }
    if id == crate::wizard::ONBOARDING_MODEL_WIZARD_ID {
        let current = ConfigDoc::load(&global_config)
            .ok()
            .map(|doc| doc.providers())
            .unwrap_or_default();
        return Some(crate::wizard::onboarding_model_descriptor_with_selection(
            &current, None,
        ));
    }
    if id == crate::wizard::ONBOARDING_PROFILE_WIZARD_ID {
        return Some(crate::wizard::onboarding_profile_descriptor());
    }
    if id == crate::wizard::ONBOARDING_AGENT_WIZARD_ID {
        let current = ConfigDoc::load(&global_config)
            .ok()
            .map(|doc| doc.providers())
            .unwrap_or_default();
        let catalog = crate::daemon::agent_catalog::preferred_catalog_for_discovery().ok()?;
        return Some(crate::wizard::onboarding_agent_descriptor(
            &current,
            &catalog.index,
            catalog.revision,
        ));
    }
    if id == crate::wizard::ONBOARDING_LIFETIME_WIZARD_ID {
        return Some(crate::wizard::onboarding_lifetime_descriptor());
    }
    crate::wizard::descriptor(id)
}

/// Model-wizard descriptor for `cwd`, optionally opening on a specific
/// `(provider_id, model_id)` rather than the first entry.
pub fn model_descriptor_for_cwd(_cwd: &Path, preselect: Option<(&str, &str)>) -> WizardDescriptor {
    let current = global_config_file()
        .ok()
        .and_then(|path| ConfigDoc::load(&path).ok())
        .map(|doc| doc.providers())
        .unwrap_or_default();
    crate::wizard::model_descriptor_with_selection(&current, preselect)
}

pub fn onboarding_model_descriptor_for_cwd(
    _cwd: &Path,
    preselect: Option<(&str, &str)>,
) -> WizardDescriptor {
    let current = global_config_file()
        .ok()
        .and_then(|path| ConfigDoc::load(&path).ok())
        .map(|doc| doc.providers())
        .unwrap_or_default();
    crate::wizard::onboarding_model_descriptor_with_selection(&current, preselect)
}

/// Where onboarding security answers are written: the always-writable global
/// layer. Workspace trust never selects or gates this path.
pub fn security_config_path() -> Result<PathBuf> {
    global_config_file().context("resolving global config for security setup")
}

/// Persist the security wizard's answers: sandbox default mode, default
/// approval mode, and the redaction minimum
/// secret length. Each field is written only when the answer differs from
/// the effective value, so an all-defaults run writes nothing and returns
/// `Ok(None)`; otherwise returns the config file that was written.
pub fn apply_security_answers(cwd: &Path, run: &WizardRun) -> Result<Option<PathBuf>> {
    apply_security_answers_with_caps(cwd, run, None)
}

/// Apply setup answers after the daemon has reconstructed and validated the
/// current wizard descriptor. This is the owner boundary used by CLI setup;
/// all writes retain the existing config lock/reload/atomic semantics.
pub fn apply_setup_wizard_answers(
    cwd: &Path,
    wizard_id: &str,
    answers_json: &str,
) -> Result<(bool, bool, Option<String>)> {
    if !matches!(
        wizard_id,
        crate::wizard::SECURITY_WIZARD_ID
            | crate::wizard::MODEL_WIZARD_ID
            | crate::wizard::ONBOARDING_MODEL_WIZARD_ID
            | crate::wizard::ONBOARDING_PROFILE_WIZARD_ID
            | crate::wizard::ONBOARDING_AGENT_WIZARD_ID
            | crate::wizard::ONBOARDING_LIFETIME_WIZARD_ID
    ) {
        return Err(anyhow!("unsupported setup wizard `{wizard_id}`"));
    }
    let descriptor = descriptor_for_cwd(wizard_id, cwd)
        .ok_or_else(|| anyhow!("unknown setup wizard `{wizard_id}`"))?;
    let run = WizardRun::from_answers_json(descriptor, answers_json)?;
    if wizard_id == crate::wizard::ONBOARDING_PROFILE_WIZARD_ID {
        let changed = apply_onboarding_profile_answers(&run)?.is_some();
        return Ok((changed, false, None));
    }
    if wizard_id == crate::wizard::ONBOARDING_LIFETIME_WIZARD_ID {
        let changed = apply_onboarding_lifetime_answers(&run)?.is_some();
        return Ok((changed, false, None));
    }
    if wizard_id == crate::wizard::SECURITY_WIZARD_ID {
        let changed = apply_security_answers(cwd, &run)?.is_some();
        return Ok((changed, false, None));
    }
    let outcome = apply_model_answers(cwd, &run)?;
    Ok((
        !outcome.changed_nothing(),
        outcome.model_file.is_some(),
        outcome.default_scope,
    ))
}

/// Daemon-owned setup application. Host capabilities are probed by the
/// daemon at the owner boundary, so a CLI-provided snapshot cannot authorize
/// an unavailable sandbox mode.
pub async fn apply_setup_wizard_answers_authoritative(
    cwd: &Path,
    wizard_id: &str,
    answers_json: &str,
) -> Result<(bool, bool, Option<String>)> {
    if !matches!(
        wizard_id,
        crate::wizard::SECURITY_WIZARD_ID
            | crate::wizard::MODEL_WIZARD_ID
            | crate::wizard::ONBOARDING_MODEL_WIZARD_ID
            | crate::wizard::ONBOARDING_PROFILE_WIZARD_ID
            | crate::wizard::ONBOARDING_AGENT_WIZARD_ID
            | crate::wizard::ONBOARDING_LIFETIME_WIZARD_ID
    ) {
        return Err(anyhow!("unsupported setup wizard `{wizard_id}`"));
    }
    let caps = compose_wizard_host_capabilities(cwd).await;
    let descriptor = descriptor_for_cwd_with_caps(wizard_id, cwd, Some(&caps))
        .ok_or_else(|| anyhow!("unknown setup wizard `{wizard_id}`"))?;
    let run = WizardRun::from_answers_json(descriptor, answers_json)?;
    if wizard_id == crate::wizard::ONBOARDING_PROFILE_WIZARD_ID {
        let changed = apply_onboarding_profile_answers(&run)?.is_some();
        return Ok((changed, false, None));
    }
    if wizard_id == crate::wizard::ONBOARDING_LIFETIME_WIZARD_ID {
        let changed = apply_onboarding_lifetime_answers(&run)?.is_some();
        return Ok((changed, false, None));
    }
    if wizard_id == crate::wizard::SECURITY_WIZARD_ID {
        let changed = apply_security_answers_with_caps(cwd, &run, Some(&caps))?.is_some();
        return Ok((changed, false, None));
    }
    let outcome = apply_model_answers(cwd, &run)?;
    Ok((
        !outcome.changed_nothing(),
        outcome.model_file.is_some(),
        outcome.default_scope,
    ))
}

fn apply_onboarding_profile_answers(run: &WizardRun) -> Result<Option<PathBuf>> {
    let target = global_config_file().context("resolving global config for onboarding profile")?;
    let mut doc = ExtendedConfigDoc::load(&target)?;
    let mut config = doc.config();
    let next = crate::wizard::onboarding_name_answer(run);
    if config.name == next {
        return Ok(None);
    }
    config.name = next;
    doc.write(&config)?;
    Ok(Some(target))
}

fn apply_onboarding_lifetime_answers(run: &WizardRun) -> Result<Option<PathBuf>> {
    let target = global_config_file().context("resolving global config for onboarding lifetime")?;
    let mut doc = ExtendedConfigDoc::load(&target)?;
    let mut config = doc.config();
    let background_agents = crate::wizard::onboarding_background_agents_answer(run)
        .context("background agent lifetime answer")?;
    if config.daemon.background_agents == background_agents {
        return Ok(None);
    }
    config.daemon.background_agents = background_agents;
    doc.write(&config)?;
    // TODO(#274): a live ephemeral owner is not promoted in place when this
    // setting changes to persistent; the choice applies to later acquisition.
    Ok(Some(target))
}

/// Persist security-wizard answers. When `caps` is present, unavailable
/// sandbox modes are refused and not written.
pub fn apply_security_answers_with_caps(
    _cwd: &Path,
    run: &WizardRun,
    caps: Option<&cockpit_proto::HostCapabilitySnapshot>,
) -> Result<Option<PathBuf>> {
    let target = security_config_path()?;
    let mut doc = ExtendedConfigDoc::load(&target)?;
    // Onboarding owns only the canonical global layer. A workspace overlay
    // must neither suppress nor redirect a user-global choice.
    let effective = doc.config();
    let mut cfg = doc.config();
    let mut changed = false;

    if let Some(mode) = sandbox_mode_answer(run)
        && mode != effective.sandbox.default_mode
    {
        if let Some(caps) = caps
            && !crate::daemon::session_worker::sandbox_mode_selectable(mode.into(), caps)
        {
            return Err(anyhow!(
                "sandbox mode `{}` is not available on this host",
                crate::wizard::sandbox_mode_id(mode)
            ));
        }
        cfg.sandbox.default_mode = mode;
        changed = true;
    }
    if let Some(mode) = approval_mode_answer(run)
        && mode != effective.default_approval_mode
    {
        cfg.default_approval_mode = mode;
        changed = true;
    }
    if let Some(min_secret_length) = min_secret_length_answer(run)
        && min_secret_length != effective.redact.min_secret_length
    {
        cfg.redact.min_secret_length = min_secret_length;
        changed = true;
    }

    if !changed {
        return Ok(None);
    }
    doc.write(&cfg)?;
    Ok(Some(target))
}

/// What `/setup model` actually changed.
///
/// Provider/model metadata and the layer-wide default are separate
/// authorities, so they are reported separately: the metadata write names a
/// concrete file, while the default names only a safe scope label — the
/// effective-default operation owns its target layer and never exposes a
/// path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModelAnswersOutcome {
    /// Provider/model metadata file that was written, if any.
    pub model_file: Option<PathBuf>,
    /// Safe scope label of the layer that now owns the verified effective
    /// default, if the wizard's "make default" choice changed it.
    pub default_scope: Option<String>,
}

impl ModelAnswersOutcome {
    pub fn changed_nothing(&self) -> bool {
        self.model_file.is_none() && self.default_scope.is_none()
    }
}

/// Persist the model wizard's answers for the selected `provider:model`:
/// trust, capability overrides, context/output token ceilings,
/// default thinking mode, `subagent_invokable`/`can_delegate`, the system
/// prompt, and optionally the active model. Onboarding model fields belong to
/// the global config layer; workspace trust neither selects nor gates that
/// user-owned target. The "make default" choice delegates to the one
/// authoritative effective-default operation.
pub fn apply_model_answers(_cwd: &Path, run: &WizardRun) -> Result<ModelAnswersOutcome> {
    let (provider_id, model_id) = model_ref_answer(run).context("model answer")?;
    let global_config = global_config_file().context("resolving global config for model setup")?;
    let model_target =
        crate::config::providers::provider_file_path_for_config(&global_config, &provider_id)
            .context("resolving global provider config for model setup")?;
    // Model onboarding is authored against the global layer alone; resolving
    // workspace overlays here would make an untrusted project influence the
    // user's durable provider/model defaults.
    let effective = ConfigDoc::load(&global_config)?.providers();
    let mut base = effective.clone();
    if let Some(model) = base.providers.get_mut(&provider_id).and_then(|provider| {
        provider
            .models
            .iter_mut()
            .find(|model| model.id == model_id)
    }) {
        model.capability_overrides = Default::default();
    }
    let base_capabilities = base.resolve_effective_model_capabilities(
        &provider_id,
        &model_id,
        base.resolution_generation,
    );
    let current_capabilities = effective.resolve_effective_model_capabilities(
        &provider_id,
        &model_id,
        effective.resolution_generation,
    );
    let provider_read = effective
        .providers
        .get(&provider_id)
        .with_context(|| format!("provider `{provider_id}` not found"))?;
    let onboarding = run.descriptor().id == crate::wizard::ONBOARDING_MODEL_WIZARD_ID;
    if !onboarding {
        provider_read
            .models
            .iter()
            .find(|model| model.id == model_id)
            .with_context(|| format!("model `{provider_id}:{model_id}` not found"))?;
    }
    let inherited_trust = effective.provider_trust_default(&provider_id);
    let current_trust = effective.resolve_trust(&provider_id, &model_id);
    let inherited_thinking = effective.provider_default_thinking_mode_default(&provider_id);
    let current_thinking = effective.resolve_default_thinking_mode(&provider_id, &model_id);
    let inherited_subagent = effective.provider_subagent_invokable_default(&provider_id);
    let current_subagent = effective.resolve_subagent_invokable(&provider_id, &model_id);
    let inherited_can_delegate = effective.provider_can_delegate_default(&provider_id);
    let current_can_delegate = effective.resolve_can_delegate(&provider_id, &model_id);

    let mut model_doc = ConfigDoc::load(&model_target)?;
    let mut layer_cfg = model_doc.providers();
    let provider = layer_cfg.providers.entry(provider_id.clone()).or_default();
    let (model_index, model_inserted) = if let Some(index) = provider
        .models
        .iter()
        .position(|model| model.id == model_id)
    {
        (index, false)
    } else {
        provider.models.push(crate::config::providers::ModelEntry {
            id: model_id.clone(),
            ..Default::default()
        });
        (provider.models.len() - 1, true)
    };
    let model = provider
        .models
        .get_mut(model_index)
        .expect("model index was just resolved");
    let mut model_changed = model_inserted;

    if let Some(selected) = model_trust_answer(run) {
        let next = if selected == current_trust {
            model.trust
        } else if selected == inherited_trust {
            None
        } else {
            Some(selected)
        };
        if model.trust != next {
            model.trust = next;
            model_changed = true;
        }
    }

    let selected_capabilities = model_capability_answers(run);
    let configure_capabilities = run.answer("capabilities").is_some();
    let next_images = capability_status_override(
        selected_capabilities.contains("images"),
        current_capabilities.image_input.status,
        base_capabilities.image_input.status,
        model.capability_overrides.image_input,
    );
    if configure_capabilities && model.capability_overrides.image_input != next_images {
        model.capability_overrides.image_input = next_images;
        model_changed = true;
    }
    let next_tools = capability_status_override(
        selected_capabilities.contains("tools"),
        current_capabilities.tool_calling,
        base_capabilities.tool_calling,
        model.capability_overrides.tool_calling,
    );
    if configure_capabilities && model.capability_overrides.tool_calling != next_tools {
        model.capability_overrides.tool_calling = next_tools;
        model_changed = true;
    }
    let next_reasoning = capability_status_override(
        selected_capabilities.contains("reasoning"),
        current_capabilities.reasoning,
        base_capabilities.reasoning,
        model.capability_overrides.reasoning,
    );
    if configure_capabilities && model.capability_overrides.reasoning != next_reasoning {
        model.capability_overrides.reasoning = next_reasoning;
        model_changed = true;
    }
    let next_structured = capability_status_override(
        selected_capabilities.contains("structured_outputs"),
        current_capabilities.structured_outputs,
        base_capabilities.structured_outputs,
        model.capability_overrides.structured_outputs,
    );
    if configure_capabilities && model.capability_overrides.structured_outputs != next_structured {
        model.capability_overrides.structured_outputs = next_structured;
        model_changed = true;
    }

    if let Some(value) = model_context_tokens_answer(run) {
        let next = numeric_capability_override(
            Some(value),
            current_capabilities.context_tokens,
            base_capabilities.context_tokens,
            model.capability_overrides.context_tokens,
        );
        if model.capability_overrides.context_tokens != next {
            model.capability_overrides.context_tokens = next;
            model_changed = true;
        }
    }
    if let Some(value) = model_max_output_tokens_answer(run) {
        let next = numeric_capability_override(
            Some(value),
            current_capabilities.max_output_tokens,
            base_capabilities.max_output_tokens,
            model.capability_overrides.max_output_tokens,
        );
        if model.capability_overrides.max_output_tokens != next {
            model.capability_overrides.max_output_tokens = next;
            model_changed = true;
        }
    }

    if let Some(selected) = model_default_thinking_answer(run) {
        let next = if selected == current_thinking {
            model.default_thinking_mode
        } else if selected == inherited_thinking {
            None
        } else {
            selected
        };
        if model.default_thinking_mode != next {
            model.default_thinking_mode = next;
            model_changed = true;
        }
    }

    let selected_subagent = model_subagent_answers(run);
    let configure_subagents = run.answer("subagent-flags").is_some();
    let subagent_value = selected_subagent.contains("subagent_invokable");
    let next_subagent = if subagent_value == current_subagent {
        model.subagent_invokable
    } else if subagent_value == inherited_subagent {
        None
    } else {
        Some(subagent_value)
    };
    if configure_subagents && model.subagent_invokable != next_subagent {
        model.subagent_invokable = next_subagent;
        model_changed = true;
    }
    let can_delegate_value = selected_subagent.contains("can_delegate");
    let next_can_delegate = if can_delegate_value == current_can_delegate {
        model.can_delegate
    } else if can_delegate_value == inherited_can_delegate {
        None
    } else {
        Some(can_delegate_value)
    };
    if configure_subagents && model.can_delegate != next_can_delegate {
        model.can_delegate = next_can_delegate;
        model_changed = true;
    }

    let next_active =
        model_make_default_answer(run).then(|| crate::config::providers::ActiveModelRef {
            provider: provider_id.clone(),
            model: model_id.clone(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        });
    let active_changed = next_active
        .as_ref()
        .is_some_and(|active| effective.active_model.as_ref() != Some(active));

    if let Some(next) = model_system_prompt_answer(run)
        && model.system_prompt != next
    {
        model.system_prompt = next;
        model_changed = true;
    }

    if !model_changed && !active_changed {
        return Ok(ModelAnswersOutcome::default());
    }

    if model_changed {
        model_doc.write_model_wizard_fields(&provider_id, model)?;
    }

    let mut outcome = ModelAnswersOutcome {
        model_file: model_changed.then_some(model_target),
        default_scope: None,
    };
    if let Some(next) = next_active
        && active_changed
    {
        // The wizard's "make default" choice delegates to the same
        // authoritative operation as Ctrl+Enter and `/settings`; there is no
        // parallel default-persistence API.
        let result = crate::config::providers::mutate_effective_default(
            global_config
                .parent()
                .context("global config file has no parent directory")?,
            Some(&next),
            crate::config::providers::ActiveModelWriteMode::Replace,
            None,
            None,
            None,
        )
        .map_err(|error| anyhow!("{}", error.user_message))?;
        outcome.default_scope = Some(result.scope_label);
    }

    Ok(outcome)
}

fn capability_status_override(
    selected: bool,
    current: crate::config::providers::CapabilityStatus,
    base: crate::config::providers::CapabilityStatus,
    existing: Option<crate::config::providers::CapabilityStatus>,
) -> Option<crate::config::providers::CapabilityStatus> {
    use crate::config::providers::CapabilityStatus;
    let current_supported = matches!(current, CapabilityStatus::Supported);
    let base_supported = matches!(base, CapabilityStatus::Supported);
    if selected == current_supported {
        existing
    } else if selected == base_supported {
        None
    } else if selected {
        Some(CapabilityStatus::Supported)
    } else {
        Some(CapabilityStatus::Unsupported)
    }
}

fn numeric_capability_override(
    selected: Option<u32>,
    current: Option<u32>,
    base: Option<u32>,
    existing: Option<u32>,
) -> Option<u32> {
    if selected == current {
        existing
    } else if selected == base {
        None
    } else {
        selected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::dirs::{COCKPIT_CONFIG_ENV, global_config_file};
    use crate::wizard::WizardAnswer;
    use cockpit_test_support::TestEnvGuard;

    struct CockpitConfigEnvGuard {
        _guard: crate::test_env::TestEnvGuard,
    }

    impl CockpitConfigEnvGuard {
        fn set(root: &std::path::Path) -> Self {
            let guard = crate::test_env::lock();
            guard.remove_var(COCKPIT_CONFIG_ENV);
            guard.set_var("XDG_CONFIG_HOME", root.join("config"));
            guard.set_var("HOME", root.join("home"));
            guard.set_var("XDG_STATE_HOME", root.join("state"));
            guard.set_var("XDG_DATA_HOME", root.join("data"));
            guard.set_var("COCKPIT_TEST_NO_KEYRING", "1");
            Self { _guard: guard }
        }
    }

    fn write_model_wizard_provider(_cwd: &std::path::Path) -> PathBuf {
        let path = global_config_file().unwrap();
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

    fn write_model_wizard_provider_at(config_path: &std::path::Path) -> PathBuf {
        let Some(parent) = config_path.parent() else {
            panic!("config target has no parent");
        };
        std::fs::create_dir_all(parent).unwrap();
        std::fs::write(config_path, "{}").unwrap();
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
        let mut doc = ConfigDoc::load(config_path).unwrap();
        doc.write(&cfg).unwrap();
        crate::config::providers::provider_file_path_for_config(config_path, "p").unwrap()
    }

    fn submit_model_wizard_until_save(
        run: &mut WizardRun,
        capabilities: Vec<&str>,
        subagent_flags: Vec<&str>,
    ) {
        run.submit(WizardAnswer::Select("p".to_string())).unwrap();
        run.submit(WizardAnswer::Select("p:m".to_string())).unwrap();
        run.submit(WizardAnswer::Select("trusted".to_string()))
            .unwrap();
        run.submit(WizardAnswer::MultiToggle(
            capabilities.into_iter().map(str::to_string).collect(),
        ))
        .unwrap();
        run.submit(WizardAnswer::Text(String::new())).unwrap();
        run.submit(WizardAnswer::Text(String::new())).unwrap();
        if run.current_step_id() == Some("thinking") {
            run.submit(WizardAnswer::Select("inherit".to_string()))
                .unwrap();
        }
        run.submit(WizardAnswer::MultiToggle(
            subagent_flags.into_iter().map(str::to_string).collect(),
        ))
        .unwrap();
        run.submit(WizardAnswer::Confirm(true)).unwrap();
        run.submit(WizardAnswer::Select("skip".to_string()))
            .unwrap();
        assert_eq!(run.current_step_id(), Some("model-save"));
    }

    fn submit_model_wizard_prefills_until_save(run: &mut WizardRun) {
        while run.current_step_id() != Some("model-save") {
            let answer = run
                .prefill()
                .expect("current model wizard step has prefill");
            run.submit(answer).unwrap();
        }
    }

    fn submit_security_wizard_prefills_until_save(run: &mut WizardRun) {
        submit_security_wizard_until_save(run, &[]);
    }

    fn submit_security_wizard_until_save(
        run: &mut WizardRun,
        overrides: &[(&'static str, WizardAnswer)],
    ) {
        while run.current_step_id() != Some("security-save") {
            let step_id = run.current_step_id().expect("security wizard step");
            let answer = overrides
                .iter()
                .find_map(|(id, answer)| (*id == step_id).then(|| answer.clone()))
                .or_else(|| (step_id == "workspace-trust").then_some(WizardAnswer::Acknowledged))
                .or_else(|| run.prefill())
                .unwrap_or_else(|| panic!("security wizard step `{step_id}` has no answer"));
            run.submit(answer).unwrap();
        }
    }

    fn available_sandbox_caps() -> cockpit_proto::HostCapabilitySnapshot {
        crate::daemon::session_worker::sandbox_capability_snapshot(
            cockpit_proto::FeatureCapabilityState::Available,
            cockpit_proto::FeatureCapabilityState::Available,
        )
    }

    fn security_run_for_cwd(cwd: &std::path::Path) -> WizardRun {
        let caps = available_sandbox_caps();
        let descriptor =
            descriptor_for_cwd_with_caps(crate::wizard::SECURITY_WIZARD_ID, cwd, Some(&caps))
                .unwrap();
        WizardRun::new(descriptor).unwrap()
    }

    fn read_json(path: &std::path::Path) -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn trust_policy_for(
        root: &std::path::Path,
        mode: crate::db::workspace_trust::WorkspaceTrustMode,
    ) -> crate::config::trust::WorkspaceTrustPolicy {
        crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::TrustRoot {
                opened_path: root.to_path_buf(),
                root: root.to_path_buf(),
                kind: crate::config::trust::TrustRootKind::Directory,
            },
            mode,
        }
    }

    #[test]
    fn onboarding_profile_apply_writes_name_from_client_answers() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = CockpitConfigEnvGuard::set(tmp.path());
        let mut run = WizardRun::new(crate::wizard::onboarding_profile_descriptor()).unwrap();
        run.submit(WizardAnswer::Text("Ada".to_string())).unwrap();
        assert_eq!(run.current_step_id(), Some("profile-save"));
        let answers_json = run.answers_json().unwrap();

        let (changed, model_file_written, default_scope) = apply_setup_wizard_answers(
            tmp.path(),
            crate::wizard::ONBOARDING_PROFILE_WIZARD_ID,
            &answers_json,
        )
        .expect("daemon apply reconstructs profile-save and writes the name");

        assert!(changed);
        assert!(!model_file_written);
        assert_eq!(default_scope, None);
        let config = ExtendedConfigDoc::load(&global_config_file().unwrap())
            .unwrap()
            .config();
        assert_eq!(config.name.as_deref(), Some("Ada"));
    }

    #[test]
    fn security_wizard_all_defaults_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = CockpitConfigEnvGuard::set(tmp.path());
        let config_path = global_config_file().unwrap();
        let mut run = security_run_for_cwd(tmp.path());
        submit_security_wizard_prefills_until_save(&mut run);

        let saved = apply_security_answers(tmp.path(), &run).unwrap();

        assert_eq!(saved, None);
        assert!(!config_path.exists());
    }

    #[test]
    fn security_wizard_writes_only_changed_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = CockpitConfigEnvGuard::set(tmp.path());
        let config_path = global_config_file().unwrap();
        let mut run = security_run_for_cwd(tmp.path());
        submit_security_wizard_until_save(
            &mut run,
            &[(
                "sandbox",
                WizardAnswer::Select("container-readonly".to_string()),
            )],
        );

        let saved = apply_security_answers(tmp.path(), &run).unwrap();

        assert_eq!(saved.as_deref(), Some(config_path.as_path()));
        let raw = read_json(&config_path);
        assert_eq!(raw["sandbox"]["defaultMode"], "container_readonly");
        assert!(raw.get("defaultApprovalMode").is_none());
        assert!(raw.get("redact").is_none());
    }

    #[test]
    fn security_wizard_cannot_persist_unavailable_container() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = CockpitConfigEnvGuard::set(tmp.path());
        let config_path = global_config_file().unwrap();
        let caps = crate::daemon::session_worker::sandbox_capability_snapshot(
            cockpit_proto::FeatureCapabilityState::Available,
            cockpit_proto::FeatureCapabilityState::Missing,
        );
        let mut run = security_run_for_cwd(tmp.path());
        submit_security_wizard_until_save(
            &mut run,
            &[(
                "sandbox",
                WizardAnswer::Select("container-readonly".to_string()),
            )],
        );

        let err = apply_security_answers_with_caps(tmp.path(), &run, Some(&caps))
            .expect_err("unavailable container must not persist");
        assert!(err.to_string().contains("not available"));
        assert!(!config_path.exists());
    }

    #[test]
    fn security_wizard_off_sandbox_mode_persists() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = CockpitConfigEnvGuard::set(tmp.path());
        let config_path = global_config_file().unwrap();
        let mut run = security_run_for_cwd(tmp.path());
        submit_security_wizard_until_save(
            &mut run,
            &[("sandbox", WizardAnswer::Select("off".to_string()))],
        );

        let saved = apply_security_answers(tmp.path(), &run).unwrap();

        assert_eq!(saved.as_deref(), Some(config_path.as_path()));
        let cfg = crate::config::extended::load_for_cwd(tmp.path());
        assert_eq!(
            cfg.sandbox.default_mode,
            crate::tools::sandbox_mode::SandboxIntent::Off
        );
    }

    #[test]
    fn security_wizard_ignores_matching_workspace_layer_value() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = CockpitConfigEnvGuard::set(tmp.path());
        let global_config = global_config_file().unwrap();
        let parent = tmp.path().join("repo");
        let child = parent.join("child");
        let parent_config = parent.join(".cockpit/config.json");
        std::fs::create_dir_all(parent_config.parent().unwrap()).unwrap();
        std::fs::create_dir_all(&child).unwrap();
        std::fs::write(&parent_config, r#"{"sandbox":{"defaultMode":"container"}}"#).unwrap();
        let before = std::fs::read_to_string(&parent_config).unwrap();
        let policy = trust_policy_for(
            &parent,
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        );
        let saved = crate::config::trust::with_workspace_trust_policy(policy, || {
            let mut run = security_run_for_cwd(&child);
            submit_security_wizard_until_save(
                &mut run,
                &[("sandbox", WizardAnswer::Select("container".to_string()))],
            );

            apply_security_answers(&child, &run).unwrap()
        });

        assert_eq!(saved.as_deref(), Some(global_config.as_path()));
        assert_eq!(std::fs::read_to_string(&parent_config).unwrap(), before);
    }

    #[test]
    fn security_wizard_write_target_is_global_despite_workspace_layer() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = CockpitConfigEnvGuard::set(tmp.path());
        let global_config = global_config_file().unwrap();
        let project = tmp.path().join("repo");
        let project_config = project.join(".cockpit/config.json");
        std::fs::create_dir_all(project_config.parent().unwrap()).unwrap();
        std::fs::write(&project_config, "{}").unwrap();
        let policy = trust_policy_for(
            &project,
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        );
        let saved = crate::config::trust::with_workspace_trust_policy(policy, || {
            let mut run = security_run_for_cwd(&project);
            submit_security_wizard_until_save(
                &mut run,
                &[("sandbox", WizardAnswer::Select("container".to_string()))],
            );

            apply_security_answers(&project, &run).unwrap()
        });

        assert_eq!(saved.as_deref(), Some(global_config.as_path()));
        assert_eq!(std::fs::read_to_string(&project_config).unwrap(), "{}");
    }

    #[test]
    fn security_wizard_write_target_is_global_in_fresh_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path().join("repo");
        let home = tmp.path().join("home");
        let data = tmp.path().join("data");
        let state = tmp.path().join("state");
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "wizard::apply::tests::security_wizard_write_target_is_global_in_fresh_workspace_child",
                "--ignored",
                "--nocapture",
            ])
            .env("COCKPIT_SECURITY_FALLBACK_CWD", &cwd)
            .env("HOME", &home)
            .env("XDG_DATA_HOME", &data)
            .env("XDG_STATE_HOME", &state)
            .env_remove("XDG_CONFIG_HOME")
            .env_remove(COCKPIT_CONFIG_ENV)
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "fallback child failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test]
    #[ignore = "spawned by security_wizard_write_target_is_global_in_fresh_workspace"]
    async fn security_wizard_write_target_is_global_in_fresh_workspace_child() {
        let cwd = std::path::PathBuf::from(
            std::env::var_os("COCKPIT_SECURITY_FALLBACK_CWD").expect("fallback cwd env var"),
        );
        let global =
            std::path::PathBuf::from(std::env::var_os("HOME").expect("isolated home env var"))
                .join(".config/cockpit/config.json");
        assert!(!global.exists());
        let mut run = security_run_for_cwd(&cwd);
        submit_security_wizard_until_save(
            &mut run,
            &[("sandbox", WizardAnswer::Select("container".to_string()))],
        );

        let saved = apply_security_answers(&cwd, &run).unwrap();

        assert_eq!(saved.as_deref(), Some(global.as_path()));
        assert!(global.exists());
        assert!(!cwd.join(".cockpit/config.json").exists());
    }

    #[test]
    fn security_wizard_unparseable_min_secret_length_is_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = CockpitConfigEnvGuard::set(tmp.path());
        let config_path = global_config_file().unwrap();
        let mut run = security_run_for_cwd(tmp.path());
        submit_security_wizard_prefills_until_save(&mut run);
        run.answers
            .insert("redaction", WizardAnswer::Text("not-a-number".to_string()));
        run.answers
            .insert("sandbox", WizardAnswer::Select("container".to_string()));

        let saved = apply_security_answers(tmp.path(), &run).unwrap();

        assert_eq!(saved.as_deref(), Some(config_path.as_path()));
        let raw = read_json(&config_path);
        assert_eq!(raw["sandbox"]["defaultMode"], "container");
        assert!(raw.get("redact").is_none());
    }

    #[test]
    fn security_wizard_min_secret_length_trims_whitespace() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = CockpitConfigEnvGuard::set(tmp.path());
        let config_path = global_config_file().unwrap();
        let mut run = security_run_for_cwd(tmp.path());
        submit_security_wizard_until_save(
            &mut run,
            &[("redaction", WizardAnswer::Text(" 24 ".to_string()))],
        );

        let saved = apply_security_answers(tmp.path(), &run).unwrap();

        assert_eq!(saved.as_deref(), Some(config_path.as_path()));
        let cfg = crate::config::extended::load_for_cwd(tmp.path());
        assert_eq!(cfg.redact.min_secret_length, 24);
    }

    #[test]
    fn model_wizard_writes_only_changed_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = CockpitConfigEnvGuard::set(&tmp.path().join("global-config.json"));
        let path = write_model_wizard_provider(tmp.path());
        let provider_path =
            crate::config::providers::provider_file_path_for_config(&path, "p").unwrap();
        let descriptor = descriptor_for_cwd(crate::wizard::MODEL_WIZARD_ID, tmp.path()).unwrap();
        let mut run = WizardRun::new(descriptor).unwrap();
        submit_model_wizard_until_save(&mut run, vec!["images"], vec![]);

        let saved = apply_model_answers(tmp.path(), &run).unwrap();
        assert_eq!(saved.model_file.as_deref(), Some(provider_path.as_path()));
        let cfg = ConfigDoc::load_effective(tmp.path());
        let model_entry = cfg.providers["p"]
            .models
            .iter()
            .find(|model| model.id == "m")
            .unwrap();
        let model = serde_json::to_value(model_entry).unwrap();
        assert_eq!(model["trust"], "trusted");
        assert_eq!(model["capability_overrides"]["image_input"], "supported");
        assert_eq!(model["subagent_invokable"], false);
        assert_eq!(model["can_delegate"], false);
        assert!(model.get("default_thinking_mode").is_none());
        assert!(model["capability_overrides"].get("tool_calling").is_none());
        assert!(model["capability_overrides"].get("reasoning").is_none());
        assert!(
            model["capability_overrides"]
                .get("structured_outputs")
                .is_none()
        );
    }

    #[test]
    fn model_wizard_untouched_capability_stays_auto() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = CockpitConfigEnvGuard::set(&tmp.path().join("global-config.json"));
        write_model_wizard_provider(tmp.path());
        let descriptor = descriptor_for_cwd(crate::wizard::MODEL_WIZARD_ID, tmp.path()).unwrap();
        let mut run = WizardRun::new(descriptor).unwrap();
        submit_model_wizard_until_save(
            &mut run,
            vec![],
            vec!["subagent_invokable", "can_delegate"],
        );

        apply_model_answers(tmp.path(), &run).unwrap();
        let cfg = ConfigDoc::load_effective(tmp.path());
        let model = cfg.providers["p"]
            .models
            .iter()
            .find(|model| model.id == "m")
            .unwrap();
        assert_eq!(model.capability_overrides.image_input, None);
        assert_eq!(model.capability_overrides.tool_calling, None);
        assert_eq!(model.capability_overrides.reasoning, None);
        assert_eq!(model.capability_overrides.structured_outputs, None);
    }

    #[test]
    fn model_wizard_detected_supported_prefill_writes_no_capability_override() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = CockpitConfigEnvGuard::set(&tmp.path().join("global-config.json"));
        let path = write_model_wizard_provider(tmp.path());
        let mut doc = ConfigDoc::load(&path).unwrap();
        let mut cfg = doc.providers();
        let provider = cfg.providers.get_mut("p").unwrap();
        provider.trust = Some(crate::config::providers::ModelTrust::Trusted);
        let model = provider
            .models
            .iter_mut()
            .find(|model| model.id == "m")
            .unwrap();
        model.capabilities.image_input = crate::config::providers::CapabilityStatus::Supported;
        model.capabilities.tool_calling = crate::config::providers::CapabilityStatus::Supported;
        model.capabilities.reasoning = crate::config::providers::CapabilityStatus::Supported;
        model.capabilities.structured_outputs =
            crate::config::providers::CapabilityStatus::Supported;
        model.capabilities.context_tokens = Some(128_000);
        model.capabilities.max_output_tokens = Some(8192);
        doc.write(&cfg).unwrap();
        let descriptor = descriptor_for_cwd(crate::wizard::MODEL_WIZARD_ID, tmp.path()).unwrap();
        let mut run = WizardRun::new(descriptor).unwrap();
        submit_model_wizard_prefills_until_save(&mut run);

        let saved = apply_model_answers(tmp.path(), &run).unwrap();

        assert!(saved.changed_nothing(), "{saved:?}");
        let cfg = ConfigDoc::load_effective(tmp.path());
        let model = cfg.providers["p"]
            .models
            .iter()
            .find(|model| model.id == "m")
            .unwrap();
        assert_eq!(model.trust, None);
        assert_eq!(model.capability_overrides.image_input, None);
        assert_eq!(model.capability_overrides.tool_calling, None);
        assert_eq!(model.capability_overrides.reasoning, None);
        assert_eq!(model.capability_overrides.structured_outputs, None);
        assert_eq!(model.capability_overrides.context_tokens, None);
        assert_eq!(model.capability_overrides.max_output_tokens, None);
        assert_eq!(model.subagent_invokable, None);
        assert_eq!(model.can_delegate, None);
    }

    #[test]
    fn model_wizard_prefill_preserves_existing_explicit_overrides() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = CockpitConfigEnvGuard::set(&tmp.path().join("global-config.json"));
        let path = write_model_wizard_provider(tmp.path());
        let mut doc = ConfigDoc::load(&path).unwrap();
        let mut cfg = doc.providers();
        let model = cfg
            .providers
            .get_mut("p")
            .unwrap()
            .models
            .iter_mut()
            .find(|model| model.id == "m")
            .unwrap();
        model.capabilities.image_input = crate::config::providers::CapabilityStatus::Supported;
        model.capability_overrides.image_input =
            Some(crate::config::providers::CapabilityStatus::Unsupported);
        model.can_delegate = Some(false);
        doc.write(&cfg).unwrap();
        let before = std::fs::read_to_string(&path).unwrap();
        let descriptor = descriptor_for_cwd(crate::wizard::MODEL_WIZARD_ID, tmp.path()).unwrap();
        let mut run = WizardRun::new(descriptor).unwrap();
        submit_model_wizard_prefills_until_save(&mut run);

        let saved = apply_model_answers(tmp.path(), &run).unwrap();

        assert!(saved.changed_nothing(), "{saved:?}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }

    #[test]
    fn model_wizard_trust_step_inherit_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = CockpitConfigEnvGuard::set(&tmp.path().join("global-config.json"));
        let path = write_model_wizard_provider(tmp.path());
        let mut doc = ConfigDoc::load(&path).unwrap();
        let mut cfg = doc.providers();
        cfg.providers.get_mut("p").unwrap().trust =
            Some(crate::config::providers::ModelTrust::Trusted);
        doc.write(&cfg).unwrap();
        let descriptor = descriptor_for_cwd(crate::wizard::MODEL_WIZARD_ID, tmp.path()).unwrap();
        let mut run = WizardRun::new(descriptor).unwrap();
        run.submit(WizardAnswer::Select("p".to_string())).unwrap();
        run.submit(WizardAnswer::Select("p:m".to_string())).unwrap();
        assert_eq!(run.current_step_id(), Some("trust"));
        assert!(run.help().contains("provider default: trusted"));
        run.back();
        run.back();
        submit_model_wizard_until_save(
            &mut run,
            vec![],
            vec!["subagent_invokable", "can_delegate"],
        );
        apply_model_answers(tmp.path(), &run).unwrap();
        let cfg = ConfigDoc::load_effective(tmp.path());
        let model = cfg.providers["p"]
            .models
            .iter()
            .find(|model| model.id == "m")
            .unwrap();
        assert_eq!(model.trust, None);
    }

    /// Setup surface: both trust values must go *through the setup wizard* —
    /// offered, accepted, written by `apply_model_answers`, and resolving back
    /// as exactly the custody class that was submitted.
    #[test]
    fn trust_configuration_through_setup() {
        use crate::config::providers::ModelTrust;

        for trust_id in ["trusted", "untrusted"] {
            let tmp = tempfile::tempdir().unwrap();
            let _guard = CockpitConfigEnvGuard::set(&tmp.path().join("global-config.json"));
            write_model_wizard_provider(tmp.path());
            let descriptor =
                descriptor_for_cwd(crate::wizard::MODEL_WIZARD_ID, tmp.path()).unwrap();
            let mut run = WizardRun::new(descriptor).unwrap();

            run.submit(WizardAnswer::Select("p".to_string())).unwrap();
            run.submit(WizardAnswer::Select("p:m".to_string())).unwrap();

            assert_eq!(run.current_step_id(), Some("trust"));
            let trust_options: Vec<String> = run
                .select_options()
                .into_iter()
                .map(|o| o.id.to_string())
                .collect();
            for id in ["untrusted", "trusted"] {
                assert!(
                    trust_options.iter().any(|o| o == id),
                    "{trust_id}: every custody class must stay offered: {trust_options:?}"
                );
            }
            run.submit(WizardAnswer::Select(trust_id.to_string()))
                .unwrap_or_else(|e| panic!("{trust_id}: trust rejected: {e}"));

            let expected_trust = match trust_id {
                "trusted" => ModelTrust::Trusted,
                _ => ModelTrust::Untrusted,
            };
            assert_eq!(
                crate::wizard::model_trust_answer(&run),
                Some(expected_trust),
                "{trust_id}: the wizard must hold the submitted custody answer"
            );

            run.submit(WizardAnswer::MultiToggle(Vec::new())).unwrap();
            run.submit(WizardAnswer::Text(String::new())).unwrap();
            run.submit(WizardAnswer::Text(String::new())).unwrap();
            if run.current_step_id() == Some("thinking") {
                run.submit(WizardAnswer::Select("inherit".to_string()))
                    .unwrap();
            }
            run.submit(WizardAnswer::MultiToggle(Vec::new())).unwrap();
            run.submit(WizardAnswer::Confirm(true)).unwrap();
            run.submit(WizardAnswer::Select("skip".to_string()))
                .unwrap();
            assert_eq!(run.current_step_id(), Some("model-save"));

            apply_model_answers(tmp.path(), &run)
                .unwrap_or_else(|e| panic!("{trust_id}: save rejected: {e:#}"));

            let cfg = ConfigDoc::load_effective(tmp.path());
            assert_eq!(
                cfg.resolve_trust("p", "m"),
                expected_trust,
                "{trust_id}: setup must persist the submitted custody class"
            );
        }
    }

    #[test]
    fn model_wizard_saves_model_from_outer_layer() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();
        let project = tmp.path().join("repo");
        let project_config = project.join(".cockpit/config.json");
        std::fs::create_dir_all(project_config.parent().unwrap()).unwrap();
        let home_config = tmp.path().join("home/.config/cockpit/config.json");
        let home_provider = write_model_wizard_provider_at(&home_config);
        std::fs::write(&project_config, "{}").unwrap();

        let policy = trust_policy_for(
            &project,
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        );
        let saved = crate::config::trust::with_workspace_trust_policy(policy, || {
            let descriptor = descriptor_for_cwd(crate::wizard::MODEL_WIZARD_ID, &project).unwrap();
            let mut run = WizardRun::new(descriptor).unwrap();
            submit_model_wizard_until_save(&mut run, vec!["images"], vec![]);
            apply_model_answers(&project, &run).unwrap()
        });

        assert_eq!(saved.model_file.as_deref(), Some(home_provider.as_path()));
        let home_cfg = ConfigDoc::load(&home_config).unwrap().providers();
        let model = home_cfg.providers["p"]
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
        assert!(
            !crate::config::providers::provider_file_path_for_config(&project_config, "p")
                .unwrap()
                .exists()
        );
        let global_cfg = ConfigDoc::load(&home_config).unwrap().providers();
        assert_eq!(global_cfg.active_model.as_ref().unwrap().provider, "p");
        assert_eq!(global_cfg.active_model.as_ref().unwrap().model, "m");
        assert!(
            ConfigDoc::load(&project_config)
                .unwrap()
                .providers()
                .active_model
                .is_none()
        );
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    #[test]
    fn model_wizard_ignores_workspace_overlay_layer_for_global_write() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();
        let project = tmp.path().join("repo");
        let project_config = project.join(".cockpit/config.json");
        std::fs::create_dir_all(project_config.parent().unwrap()).unwrap();
        let home_config = tmp.path().join("home/.config/cockpit/config.json");
        let home_provider = write_model_wizard_provider_at(&home_config);
        std::fs::write(&project_config, "{}").unwrap();
        let before_project = std::fs::read_to_string(&project_config).unwrap();
        let project_provider =
            crate::config::providers::provider_file_path_for_config(&project_config, "p").unwrap();
        std::fs::create_dir_all(project_provider.parent().unwrap()).unwrap();
        std::fs::write(
            &project_provider,
            r#"{"models":[{"id":"other","trust":"trusted"}]}"#,
        )
        .unwrap();

        let policy = trust_policy_for(
            &project,
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        );
        let saved = crate::config::trust::with_workspace_trust_policy(policy, || {
            let descriptor = descriptor_for_cwd(
                crate::wizard::MODEL_WIZARD_ID,
                home_config.parent().unwrap(),
            )
            .unwrap();
            let mut run = WizardRun::new(descriptor).unwrap();
            submit_model_wizard_until_save(&mut run, vec!["images"], vec![]);
            apply_model_answers(&project, &run).unwrap()
        });

        assert_eq!(saved.model_file.as_deref(), Some(home_provider.as_path()));
        assert_eq!(
            std::fs::read_to_string(&project_config).unwrap(),
            before_project
        );
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&home_provider).unwrap()).unwrap();
        let models = raw["models"].as_array().unwrap();
        let overlay = models.iter().find(|model| model["id"] == "m").unwrap();
        assert_eq!(overlay["trust"], "trusted");
        assert_eq!(overlay["capability_overrides"]["image_input"], "supported");
        assert_eq!(raw["url"], "http://localhost:1/v1");
        assert!(
            std::fs::read_to_string(&project_provider)
                .unwrap()
                .contains("other")
        );
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    #[test]
    fn model_wizard_unwritable_layer_errors_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = CockpitConfigEnvGuard::set(tmp.path());
        let mut cfg = crate::config::providers::ProvidersConfig::default();
        let mut provider = crate::config::providers::ProviderEntry {
            url: "http://localhost:1/v1".to_string(),
            ..Default::default()
        };
        provider.models.push(crate::config::providers::ModelEntry {
            id: "m".to_string(),
            ..Default::default()
        });
        cfg.providers.insert("bad/provider".to_string(), provider);
        let descriptor =
            crate::wizard::model_descriptor_with_selection(&cfg, Some(("bad/provider", "m")));
        let mut run = WizardRun::new(descriptor).unwrap();
        run.submit(WizardAnswer::Select("bad/provider".to_string()))
            .unwrap();
        run.submit(WizardAnswer::Select("bad/provider:m".to_string()))
            .unwrap();

        let error = apply_model_answers(std::path::Path::new("."), &run)
            .unwrap_err()
            .to_string();

        assert!(error.contains("bad/provider"));
        assert!(error.contains("writable"));
        assert!(!error.contains("not found"));
    }

    #[test]
    fn apply_setup_wizard_answers_persists_onboarding_profile_from_client_answers_json() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = CockpitConfigEnvGuard::set(tmp.path());
        let mut run = WizardRun::new(crate::wizard::onboarding_profile_descriptor()).unwrap();
        run.submit(WizardAnswer::Text("Ada".into())).unwrap();
        assert_eq!(run.current_step_id(), Some("profile-save"));
        let answers_json = run.answers_json().expect("client answers_json");

        let (changed, model_file_written, default_scope) = apply_setup_wizard_answers(
            tmp.path(),
            crate::wizard::ONBOARDING_PROFILE_WIZARD_ID,
            &answers_json,
        )
        .expect("daemon apply infers profile-save and persists the name");
        assert!(changed);
        assert!(!model_file_written);
        assert!(default_scope.is_none());

        run.submit(WizardAnswer::Acknowledged)
            .expect("TUI completion submit after daemon apply");
        assert!(run.is_complete());

        let config_path = global_config_file().unwrap();
        let cfg = crate::config::extended::ExtendedConfigDoc::load(&config_path)
            .unwrap()
            .config();
        assert_eq!(cfg.name.as_deref(), Some("Ada"));
    }

    #[test]
    fn apply_setup_wizard_answers_accepts_blank_onboarding_profile_name() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = CockpitConfigEnvGuard::set(tmp.path());
        let mut run = WizardRun::new(crate::wizard::onboarding_profile_descriptor()).unwrap();
        run.submit(WizardAnswer::Text(String::new())).unwrap();
        let answers_json = run.answers_json().expect("client answers_json");

        let (changed, model_file_written, default_scope) = apply_setup_wizard_answers(
            tmp.path(),
            crate::wizard::ONBOARDING_PROFILE_WIZARD_ID,
            &answers_json,
        )
        .expect("blank name is a skip, not a missing saving step");
        assert!(!changed);
        assert!(!model_file_written);
        assert!(default_scope.is_none());

        run.submit(WizardAnswer::Acknowledged)
            .expect("TUI completion submit after skipped name");
        assert!(run.is_complete());
    }

    #[test]
    fn model_wizard_thinking_step_hidden_without_reasoning() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = CockpitConfigEnvGuard::set(&tmp.path().join("global-config.json"));
        write_model_wizard_provider(tmp.path());
        let descriptor = descriptor_for_cwd(crate::wizard::MODEL_WIZARD_ID, tmp.path()).unwrap();
        let mut run = WizardRun::new(descriptor).unwrap();
        run.submit(WizardAnswer::Select("p".to_string())).unwrap();
        run.submit(WizardAnswer::Select("p:m".to_string())).unwrap();
        run.submit(WizardAnswer::Select("untrusted".to_string()))
            .unwrap();
        run.submit(WizardAnswer::MultiToggle(Vec::new())).unwrap();
        run.submit(WizardAnswer::Text(String::new())).unwrap();
        run.submit(WizardAnswer::Text(String::new())).unwrap();
        assert_eq!(run.current_step_id(), Some("subagent-flags"));
    }

    #[test]
    fn model_wizard_abort_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = CockpitConfigEnvGuard::set(&tmp.path().join("global-config.json"));
        let path = write_model_wizard_provider(tmp.path());
        let before = std::fs::read_to_string(&path).unwrap();
        let descriptor = descriptor_for_cwd(crate::wizard::MODEL_WIZARD_ID, tmp.path()).unwrap();
        let mut run = WizardRun::new(descriptor).unwrap();
        run.submit(WizardAnswer::Select("p".to_string())).unwrap();
        run.submit(WizardAnswer::Select("p:m".to_string())).unwrap();
        run.abort();

        assert!(run.is_aborted());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }

    #[test]
    fn apply_setup_wizard_answers_persists_onboarding_profile_name() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = CockpitConfigEnvGuard::set(tmp.path());
        let config_path = global_config_file().unwrap();
        let mut run = WizardRun::new(crate::wizard::onboarding_profile_descriptor()).unwrap();
        run.submit(WizardAnswer::Text("Ada".into())).unwrap();
        assert_eq!(run.current_step_id(), Some("profile-save"));
        let answers_json = run.answers_json().unwrap();

        let (changed, model_file, default_scope) = apply_setup_wizard_answers(
            tmp.path(),
            crate::wizard::ONBOARDING_PROFILE_WIZARD_ID,
            &answers_json,
        )
        .expect("profile apply must replay the inferred save acknowledgement");

        assert!(changed);
        assert!(!model_file);
        assert_eq!(default_scope, None);
        let cfg = ExtendedConfigDoc::load(&config_path).unwrap().config();
        assert_eq!(cfg.name.as_deref(), Some("Ada"));
    }

    #[test]
    fn apply_setup_wizard_answers_persists_onboarding_lifetime_choice() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = CockpitConfigEnvGuard::set(tmp.path());
        let config_path = global_config_file().unwrap();
        let mut run = WizardRun::new(crate::wizard::onboarding_lifetime_descriptor()).unwrap();
        run.submit(WizardAnswer::Confirm(false)).unwrap();
        assert_eq!(run.current_step_id(), Some("lifetime-save"));
        let answers_json = run.answers_json().unwrap();

        let (changed, model_file, default_scope) = apply_setup_wizard_answers(
            tmp.path(),
            crate::wizard::ONBOARDING_LIFETIME_WIZARD_ID,
            &answers_json,
        )
        .expect("lifetime apply must replay the inferred save acknowledgement");

        assert!(changed);
        assert!(!model_file);
        assert_eq!(default_scope, None);
        let cfg = ExtendedConfigDoc::load(&config_path).unwrap().config();
        assert!(!cfg.daemon.background_agents);
    }
}
