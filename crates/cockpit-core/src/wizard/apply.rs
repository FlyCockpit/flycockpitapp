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
//! (`sandbox.default_mode`, `default_approval_mode`, `trusted_only`,
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

use crate::config::dirs::{
    CONFIG_FILE, config_write_target_for_provider, most_specific_config_write_target,
};
use crate::config::extended::ExtendedConfigDoc;
use crate::config::providers::ConfigDoc;
use crate::wizard::{
    WizardDescriptor, WizardRun, approval_mode_answer, min_secret_length_answer,
    model_capability_answers, model_class_answer, model_context_tokens_answer,
    model_default_thinking_answer, model_make_default_answer, model_max_output_tokens_answer,
    model_ref_answer, model_subagent_answers, model_system_prompt_answer, model_trust_answer,
    sandbox_mode_answer, trusted_only_answer,
};

/// Build the descriptor for wizard `id`, seeded from the config effective
/// at `cwd`. The security and model wizards are config-dependent (their
/// steps show current values and provider/model lists); every other wizard
/// is static and comes straight from the registry.
pub fn descriptor_for_cwd(id: &str, cwd: &Path) -> Option<WizardDescriptor> {
    if id == crate::wizard::SECURITY_WIZARD_ID {
        let current = crate::config::extended::load_for_cwd(cwd);
        return Some(crate::wizard::security_descriptor_for_config(&current));
    }
    if id == crate::wizard::MODEL_WIZARD_ID {
        return Some(model_descriptor_for_cwd(cwd, None));
    }
    crate::wizard::descriptor(id)
}

/// Model-wizard descriptor for `cwd`, optionally opening on a specific
/// `(provider_id, model_id)` rather than the first entry.
pub fn model_descriptor_for_cwd(cwd: &Path, preselect: Option<(&str, &str)>) -> WizardDescriptor {
    let current = ConfigDoc::load_effective(cwd);
    let global = crate::config::extended::load_for_cwd(cwd).llm_mode;
    crate::wizard::model_descriptor_with_selection(&current, global, preselect)
}

/// Where [`apply_security_answers`] will write: the most specific writable
/// config layer for `cwd`, falling back to `cwd/.cockpit/config.json` when
/// no layer exists yet.
pub fn security_config_path(cwd: &Path) -> PathBuf {
    most_specific_config_write_target(cwd).unwrap_or_else(|| cwd.join(".cockpit").join(CONFIG_FILE))
}

/// Persist the security wizard's answers: sandbox default mode, default
/// approval mode, workspace `trusted_only`, and the redaction minimum
/// secret length. Each field is written only when the answer differs from
/// the effective value, so an all-defaults run writes nothing and returns
/// `Ok(None)`; otherwise returns the config file that was written.
pub fn apply_security_answers(cwd: &Path, run: &WizardRun) -> Result<Option<PathBuf>> {
    let effective = crate::config::extended::load_for_cwd(cwd);
    let target = security_config_path(cwd);
    let mut doc = ExtendedConfigDoc::load(&target)?;
    let mut cfg = doc.config();
    let mut changed = false;

    if let Some(mode) = sandbox_mode_answer(run)
        && mode != effective.sandbox.default_mode
    {
        cfg.sandbox.default_mode = mode;
        changed = true;
    }
    if let Some(mode) = approval_mode_answer(run)
        && mode != effective.default_approval_mode
    {
        cfg.default_approval_mode = mode;
        changed = true;
    }
    if let Some(enabled) = trusted_only_answer(run)
        && enabled != effective.trusted_only
    {
        cfg.trusted_only = enabled;
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

/// Persist the model wizard's answers for the selected `provider:model`:
/// LLM mode, trust, capability overrides, context/output token ceilings,
/// default thinking mode, `subagent_invokable`/`can_delegate`, the system
/// prompt, and optionally the active model. Model fields go to the most
/// specific writable layer for that provider; `active_model` goes to the
/// most specific writable config layer, which may be a different file.
/// Returns `Ok(None)` when nothing changed, else the first file written.
pub fn apply_model_answers(cwd: &Path, run: &WizardRun) -> Result<Option<PathBuf>> {
    let (provider_id, model_id) = model_ref_answer(run).context("model answer")?;
    let model_target = config_write_target_for_provider(cwd, &provider_id).ok_or_else(|| {
        anyhow!("provider `{provider_id}` config is not writable; cannot save model settings")
    })?;
    let effective = ConfigDoc::load_effective(cwd);
    let mut base = effective.clone();
    if let Some(model) = base.providers.get_mut(&provider_id).and_then(|provider| {
        provider
            .models
            .iter_mut()
            .find(|model| model.id == model_id)
    }) {
        model.capability_overrides = Default::default();
    }
    let base_capabilities = base.resolve_capabilities(&provider_id, &model_id);
    let current_capabilities = effective.resolve_capabilities(&provider_id, &model_id);
    let global_mode = crate::config::extended::load_for_cwd(cwd).llm_mode;
    let provider_read = effective
        .providers
        .get(&provider_id)
        .with_context(|| format!("provider `{provider_id}` not found"))?;
    provider_read
        .models
        .iter()
        .find(|model| model.id == model_id)
        .with_context(|| format!("model `{provider_id}:{model_id}` not found"))?;
    let inherited_mode = effective.provider_mode_default(&provider_id, global_mode);
    let current_mode = effective.resolve_mode(&provider_id, &model_id, global_mode);
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
    let model_index = if let Some(index) = provider
        .models
        .iter()
        .position(|model| model.id == model_id)
    {
        index
    } else {
        provider.models.push(crate::config::providers::ModelEntry {
            id: model_id.clone(),
            ..Default::default()
        });
        provider.models.len() - 1
    };
    let model = provider
        .models
        .get_mut(model_index)
        .expect("model index was just resolved");
    let mut model_changed = false;

    if let Some(selected) = model_class_answer(run) {
        let next = if selected == current_mode {
            model.mode
        } else if selected == inherited_mode {
            None
        } else {
            Some(selected)
        };
        if model.mode != next {
            model.mode = next;
            model_changed = true;
        }
    }

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
    let next_images = capability_bool_override(
        selected_capabilities.contains("images"),
        current_capabilities.images == Some(true),
        base_capabilities.images == Some(true),
        model.capability_overrides.images,
    );
    if model.capability_overrides.images != next_images {
        model.capability_overrides.images = next_images;
        model_changed = true;
    }
    let next_tools = capability_status_override(
        selected_capabilities.contains("tools"),
        current_capabilities.tool_calling,
        base_capabilities.tool_calling,
        model.capability_overrides.tool_calling,
    );
    if model.capability_overrides.tool_calling != next_tools {
        model.capability_overrides.tool_calling = next_tools;
        model_changed = true;
    }
    let next_reasoning = capability_status_override(
        selected_capabilities.contains("reasoning"),
        current_capabilities.reasoning,
        base_capabilities.reasoning,
        model.capability_overrides.reasoning,
    );
    if model.capability_overrides.reasoning != next_reasoning {
        model.capability_overrides.reasoning = next_reasoning;
        model_changed = true;
    }
    let next_structured = capability_status_override(
        selected_capabilities.contains("structured_outputs"),
        current_capabilities.structured_outputs,
        base_capabilities.structured_outputs,
        model.capability_overrides.structured_outputs,
    );
    if model.capability_overrides.structured_outputs != next_structured {
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
    let subagent_value = selected_subagent.contains("subagent_invokable");
    let next_subagent = if subagent_value == current_subagent {
        model.subagent_invokable
    } else if subagent_value == inherited_subagent {
        None
    } else {
        Some(subagent_value)
    };
    if model.subagent_invokable != next_subagent {
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
    if model.can_delegate != next_can_delegate {
        model.can_delegate = next_can_delegate;
        model_changed = true;
    }

    let next_active =
        model_make_default_answer(run).then(|| crate::config::providers::ActiveModelRef {
            provider: provider_id.clone(),
            model: model_id.clone(),
            reasoning_effort: None,
            thinking_mode: None,
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
        return Ok(None);
    }

    if model_changed {
        model_doc.write_model_wizard_fields(&provider_id, model)?;
    }

    let mut saved = model_changed.then_some(model_target);
    if let Some(next) = next_active
        && active_changed
    {
        let active_target = most_specific_config_write_target(cwd)
            .ok_or_else(|| anyhow!("config is not writable; cannot save active_model"))?;
        let mut active_doc = ConfigDoc::load(&active_target)?;
        active_doc.write_active_model(Some(&next))?;
        if saved.is_none() {
            saved = Some(active_target);
        }
    }

    Ok(saved)
}

fn capability_bool_override(
    selected: bool,
    current_supported: bool,
    base_supported: bool,
    existing: Option<bool>,
) -> Option<bool> {
    if selected == current_supported {
        existing
    } else if selected == base_supported {
        None
    } else {
        Some(selected)
    }
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

    use crate::config::dirs::{COCKPIT_CONFIG_ENV, test_support::IsolatedCockpitHome};
    use crate::wizard::WizardAnswer;

    struct CockpitConfigEnvGuard {
        _guard: std::sync::MutexGuard<'static, ()>,
        old: Option<std::ffi::OsString>,
        old_state_home: Option<std::ffi::OsString>,
    }

    impl CockpitConfigEnvGuard {
        fn set(path: &std::path::Path) -> Self {
            Self::set_with_state(
                path,
                path.parent()
                    .unwrap_or_else(|| std::path::Path::new("/tmp")),
            )
        }

        fn set_with_state(path: &std::path::Path, state_home: &std::path::Path) -> Self {
            let guard = crate::test_env::lock();
            let old = std::env::var_os(COCKPIT_CONFIG_ENV);
            let old_state_home = std::env::var_os("XDG_STATE_HOME");
            unsafe { std::env::set_var(COCKPIT_CONFIG_ENV, path) };
            unsafe { std::env::set_var("XDG_STATE_HOME", state_home) };
            Self {
                _guard: guard,
                old,
                old_state_home,
            }
        }
    }

    impl Drop for CockpitConfigEnvGuard {
        fn drop(&mut self) {
            match &self.old {
                Some(value) => unsafe { std::env::set_var(COCKPIT_CONFIG_ENV, value) },
                None => unsafe { std::env::remove_var(COCKPIT_CONFIG_ENV) },
            }
            match &self.old_state_home {
                Some(value) => unsafe { std::env::set_var("XDG_STATE_HOME", value) },
                None => unsafe { std::env::remove_var("XDG_STATE_HOME") },
            }
        }
    }

    fn write_model_wizard_provider(cwd: &std::path::Path) -> PathBuf {
        let path = most_specific_config_write_target(cwd)
            .unwrap_or_else(|| cwd.join(".cockpit").join(crate::config::dirs::CONFIG_FILE));
        let Some(parent) = path.parent() else {
            panic!("config target has no parent");
        };
        std::fs::create_dir_all(parent).unwrap();
        std::fs::write(&path, r#"{"llm_mode":"defensive"}"#).unwrap();
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
                images: Some(false),
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
        std::fs::write(config_path, r#"{"llm_mode":"defensive"}"#).unwrap();
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
                images: Some(false),
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
        run.submit(WizardAnswer::Select("frontier".to_string()))
            .unwrap();
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
        assert_eq!(saved.as_deref(), Some(provider_path.as_path()));
        let cfg = ConfigDoc::load_effective(tmp.path());
        let model_entry = cfg.providers["p"]
            .models
            .iter()
            .find(|model| model.id == "m")
            .unwrap();
        let model = serde_json::to_value(model_entry).unwrap();
        assert_eq!(model["mode"], "frontier");
        assert_eq!(model["trust"], "trusted");
        assert_eq!(model["capability_overrides"]["images"], true);
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
        assert_eq!(model.capability_overrides.images, None);
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
        model.capabilities.images = Some(true);
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

        assert_eq!(saved, None);
        let cfg = ConfigDoc::load_effective(tmp.path());
        let model = cfg.providers["p"]
            .models
            .iter()
            .find(|model| model.id == "m")
            .unwrap();
        assert_eq!(model.trust, None);
        assert_eq!(model.capability_overrides.images, None);
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
        model.capabilities.images = Some(true);
        model.capability_overrides.images = Some(false);
        model.can_delegate = Some(false);
        doc.write(&cfg).unwrap();
        let before = std::fs::read_to_string(&path).unwrap();
        let descriptor = descriptor_for_cwd(crate::wizard::MODEL_WIZARD_ID, tmp.path()).unwrap();
        let mut run = WizardRun::new(descriptor).unwrap();
        submit_model_wizard_prefills_until_save(&mut run);

        let saved = apply_model_answers(tmp.path(), &run).unwrap();

        assert_eq!(saved, None);
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
        run.submit(WizardAnswer::Select("defensive".to_string()))
            .unwrap();
        assert!(run.help().contains("provider default: trusted"));
        run.back();
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

    #[test]
    fn model_wizard_saves_model_from_outer_layer() {
        let tmp = tempfile::tempdir().unwrap();
        let _setup_env_lock = crate::test_env::lock();
        let _env = IsolatedCockpitHome::new(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();
        let project = tmp.path().join("repo");
        let project_config = project.join(".cockpit/config.json");
        std::fs::create_dir_all(project_config.parent().unwrap()).unwrap();
        let home_config = tmp.path().join("home/.config/cockpit/config.json");
        let home_provider = write_model_wizard_provider_at(&home_config);
        std::fs::write(&project_config, "{}").unwrap();

        let descriptor = descriptor_for_cwd(crate::wizard::MODEL_WIZARD_ID, &project).unwrap();
        let mut run = WizardRun::new(descriptor).unwrap();
        submit_model_wizard_until_save(&mut run, vec!["images"], vec![]);

        let saved = apply_model_answers(&project, &run).unwrap();

        assert_eq!(saved.as_deref(), Some(home_provider.as_path()));
        let home_cfg = ConfigDoc::load(&home_config).unwrap().providers();
        let model = home_cfg.providers["p"]
            .models
            .iter()
            .find(|model| model.id == "m")
            .unwrap();
        assert_eq!(model.mode, Some(crate::config::extended::LlmMode::Frontier));
        assert_eq!(
            model.trust,
            Some(crate::config::providers::ModelTrust::Trusted)
        );
        assert_eq!(model.capability_overrides.images, Some(true));
        assert!(
            !crate::config::providers::provider_file_path_for_config(&project_config, "p")
                .unwrap()
                .exists()
        );
        let project_cfg = ConfigDoc::load(&project_config).unwrap().providers();
        assert_eq!(project_cfg.active_model.as_ref().unwrap().provider, "p");
        assert_eq!(project_cfg.active_model.as_ref().unwrap().model, "m");
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    #[test]
    fn model_wizard_partial_overlay_layer_write() {
        let tmp = tempfile::tempdir().unwrap();
        let _setup_env_lock = crate::test_env::lock();
        let _env = IsolatedCockpitHome::new(tmp.path());
        crate::config::trust::clear_runtime_policy_for_tests();
        let project = tmp.path().join("repo");
        let project_config = project.join(".cockpit/config.json");
        std::fs::create_dir_all(project_config.parent().unwrap()).unwrap();
        let home_config = tmp.path().join("home/.config/cockpit/config.json");
        let home_provider = write_model_wizard_provider_at(&home_config);
        let before_home = std::fs::read_to_string(&home_provider).unwrap();
        std::fs::write(&project_config, "{}").unwrap();
        let project_provider =
            crate::config::providers::provider_file_path_for_config(&project_config, "p").unwrap();
        std::fs::create_dir_all(project_provider.parent().unwrap()).unwrap();
        std::fs::write(
            &project_provider,
            r#"{"models":[{"id":"other","trust":"trusted"}]}"#,
        )
        .unwrap();

        let descriptor = descriptor_for_cwd(crate::wizard::MODEL_WIZARD_ID, &project).unwrap();
        let mut run = WizardRun::new(descriptor).unwrap();
        submit_model_wizard_until_save(&mut run, vec!["images"], vec![]);

        let saved = apply_model_answers(&project, &run).unwrap();

        assert_eq!(saved.as_deref(), Some(project_provider.as_path()));
        assert_eq!(
            std::fs::read_to_string(&home_provider).unwrap(),
            before_home
        );
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&project_provider).unwrap()).unwrap();
        let models = raw["models"].as_array().unwrap();
        assert!(models.iter().any(|model| model["id"] == "other"));
        let overlay = models.iter().find(|model| model["id"] == "m").unwrap();
        assert_eq!(overlay["mode"], "frontier");
        assert_eq!(overlay["trust"], "trusted");
        assert_eq!(overlay["capability_overrides"]["images"], true);
        assert!(raw.get("url").is_none());
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    #[test]
    fn model_wizard_unwritable_layer_errors_cleanly() {
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
        let descriptor = crate::wizard::model_descriptor_with_selection(
            &cfg,
            crate::config::extended::LlmMode::Normal,
            Some(("bad/provider", "m")),
        );
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
    fn model_wizard_thinking_step_hidden_without_reasoning() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = CockpitConfigEnvGuard::set(&tmp.path().join("global-config.json"));
        write_model_wizard_provider(tmp.path());
        let descriptor = descriptor_for_cwd(crate::wizard::MODEL_WIZARD_ID, tmp.path()).unwrap();
        let mut run = WizardRun::new(descriptor).unwrap();
        run.submit(WizardAnswer::Select("p".to_string())).unwrap();
        run.submit(WizardAnswer::Select("p:m".to_string())).unwrap();
        run.submit(WizardAnswer::Select("normal".to_string()))
            .unwrap();
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
        run.submit(WizardAnswer::Select("frontier".to_string()))
            .unwrap();
        run.abort();

        assert!(run.is_aborted());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }
}
