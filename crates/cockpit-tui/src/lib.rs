//! Ratatui terminal interface for the `cockpit` binary.
//!
//! This crate owns terminal rendering, input handling, panes, overlays, and
//! local clipboard helpers — everything that exists because the front end is a
//! terminal. Product logic stays in `cockpit-core`, configuration in
//! `cockpit-config`, and persistence in `cockpit-db`: if a behavior would be
//! just as true of a web or native front end, it does not belong here. This
//! crate is the mirror image of the `cockpit-core` charter, which forbids
//! ratatui, crossterm, PTY widgets, and terminal renderers below this layer.
//!
//! This crate is a leaf. Only the `cockpit-cli` binary depends on it, through
//! the single sanctioned edge in `commands/tui.rs`; no other crate may, and
//! nothing here may be depended upon by `cockpit-core` or lower.
//!
//! Crate direction is one-way:
//! `cockpit-cli -> cockpit-tui -> cockpit-core -> cockpit-config/cockpit-db/cockpit-proto`;
//! the lower crates do not depend on `cockpit-tui` or `cockpit-cli`. A
//! discovered inversion is fixed by moving the symbol to its correct crate,
//! never by a shim or a circular dev-dependency.

pub mod banner;
pub mod clipboard;
pub mod tui;

pub use cockpit_config as config;
#[cfg(test)]
pub use cockpit_core::test_env;
pub use cockpit_core::{
    agents, approval, assistants, auth, auto_title, browser, computer, container, credentials,
    daemon, diagnostics, embeddings, engine, env_snapshot, envref, git, gitignore, harness, intel,
    knowledge, locks, mcp, model_system_prompt, packages, private_fs, process, providers, redact,
    secret_ref, session, skills, startup, sync, sysinfo, text, tokens, tools, user_agent, welcome,
    wizard,
};
pub use cockpit_db as db;

pub mod commands {
    pub mod learn {
        pub use crate::skills::{build_learn_prompt, subject_from_parts};
    }

    pub mod init {
        use std::path::{Path, PathBuf};

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum InitMode {
            Create,
            Update,
            Overwrite,
        }

        pub fn resolve_target(cwd: &Path, explicit: Option<&str>) -> PathBuf {
            match explicit.map(str::trim).filter(|s| !s.is_empty()) {
                Some(arg) => {
                    let path = Path::new(arg);
                    if path.is_absolute() {
                        path.to_path_buf()
                    } else {
                        cwd.join(path)
                    }
                }
                None => {
                    let cfg = crate::config::extended::load_for_cwd(cwd);
                    let name = cfg
                        .agent_guidance_files
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "AGENTS.md".to_string());
                    cwd.join(name)
                }
            }
        }

        pub fn display_target(cwd: &Path, target: &Path) -> String {
            target
                .strip_prefix(cwd)
                .unwrap_or(target)
                .display()
                .to_string()
        }

        pub fn build_init_prompt(target: &str, mode: InitMode) -> String {
            let action = match mode {
                InitMode::Create => format!("Write a new project instructions file at `{target}`."),
                InitMode::Update => format!(
                    "Update the existing project instructions file at `{target}` in place: \
                     revise and extend it, preserving the content that is still accurate."
                ),
                InitMode::Overwrite => format!(
                    "Overwrite the project instructions file at `{target}` from scratch, \
                     replacing its current content entirely."
                ),
            };
            format!(
                "{action}\n\n\
                 First explore this project — its structure, the build/test/lint commands, \
                 the languages and frameworks in use, and any conventions a contributor must \
                 follow. Then write the file via the normal file-write tool path (delegate to \
                 `builder`, the single writer). Keep it concise and genuinely useful: terse, \
                 high-signal guidance an agent or new contributor needs, not padding. \
                 Do not create or modify `config.json` or any other config file — \
                 only the instructions file at `{target}`."
            )
        }
    }

    pub mod fetch_models {
        use std::path::Path;

        use anyhow::{Context, Result};
        use cockpit_config::config::dirs::config_write_target_for_provider;
        use cockpit_config::config::providers::{ConfigDoc, ProviderEntry};

        pub fn persist_provider(cwd: &Path, provider_id: &str, entry: ProviderEntry) -> Result<()> {
            let path = config_write_target_for_provider(cwd, provider_id).ok_or_else(|| {
                anyhow::anyhow!(
                    "no cockpit config found — run `/settings` inside the TUI to create one"
                )
            })?;
            let mut doc = ConfigDoc::load(&path)?;
            doc.write_provider_models(
                provider_id,
                &entry.models,
                entry.models_fetched_at,
                entry.model_catalog,
                entry.last_model_fetch,
            )
            .context("writing config.json")
        }
    }

    pub mod export {
        use std::path::Path;
        use std::process::Command;

        use anyhow::{Context, Result, anyhow};
        use cockpit_db::db::Db;
        use cockpit_db::db::sessions::SessionRow;

        #[derive(Debug)]
        pub struct BundleSummary {
            pub session_count: usize,
            pub byte_len: usize,
        }

        pub fn write_bundle_zip(
            _db: &Db,
            target: &SessionRow,
            out_path: &Path,
            overwrite: bool,
            include_generated_artifacts: bool,
            include_sensitive: bool,
        ) -> Result<BundleSummary> {
            if out_path.exists() && !overwrite {
                anyhow::bail!(
                    "output path `{}` already exists — pass `--force` to overwrite",
                    out_path.display()
                );
            }
            let exe = std::env::current_exe().context("resolving current executable")?;
            let session = target.session_id.to_string();
            let mut command = Command::new(exe);
            command
                .arg("export")
                .arg(session)
                .arg("--output")
                .arg(out_path);
            if overwrite {
                command.arg("--force");
            }
            if include_generated_artifacts {
                command.arg("--include-generated");
            }
            if include_sensitive {
                command.arg("--include-sensitive");
            }
            let output = command.output().context("running cockpit export")?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                let message = if stderr.trim().is_empty() {
                    stdout.trim().to_string()
                } else {
                    stderr.trim().to_string()
                };
                return Err(anyhow!(
                    "cockpit export failed with status {}: {}",
                    output.status,
                    message
                ));
            }
            let byte_len = std::fs::metadata(out_path)
                .with_context(|| format!("reading export metadata `{}`", out_path.display()))?
                .len() as usize;
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(BundleSummary {
                session_count: parse_session_count(&stdout).unwrap_or(1),
                byte_len,
            })
        }

        fn parse_session_count(stdout: &str) -> Option<usize> {
            let marker = " (";
            let after = stdout.split_once(marker)?.1;
            let number = after.split_whitespace().next()?;
            number.parse().ok()
        }
    }

    pub mod setup {
        use std::path::{Path, PathBuf};

        use anyhow::{Context, Result, anyhow};
        use cockpit_config::config::dirs::{
            CONFIG_FILE, config_write_target_for_provider, most_specific_config_write_target,
        };
        use cockpit_config::config::extended::ExtendedConfigDoc;
        use cockpit_config::config::providers::{CapabilityStatus, ConfigDoc};
        use cockpit_core::wizard::{
            MODEL_WIZARD_ID, SECURITY_WIZARD_ID, WizardDescriptor, WizardRun, approval_mode_answer,
            min_secret_length_answer, model_capability_answers, model_class_answer,
            model_context_tokens_answer, model_default_thinking_answer, model_make_default_answer,
            model_max_output_tokens_answer, model_ref_answer, model_subagent_answers,
            model_system_prompt_answer, model_trust_answer, sandbox_mode_answer,
            trusted_only_answer,
        };

        pub fn descriptor_for_cwd(id: &str, cwd: &Path) -> Option<WizardDescriptor> {
            if id == SECURITY_WIZARD_ID {
                let current = cockpit_config::config::extended::load_for_cwd(cwd);
                return Some(cockpit_core::wizard::security_descriptor_for_config(
                    &current,
                ));
            }
            if id == MODEL_WIZARD_ID {
                return Some(model_descriptor_for_cwd(cwd, None));
            }
            cockpit_core::wizard::descriptor(id)
        }

        pub fn model_descriptor_for_cwd(
            cwd: &Path,
            preselect: Option<(&str, &str)>,
        ) -> WizardDescriptor {
            let current = ConfigDoc::load_effective(cwd);
            let global = cockpit_config::config::extended::load_for_cwd(cwd).llm_mode;
            cockpit_core::wizard::model_descriptor_with_selection(&current, global, preselect)
        }

        pub fn security_config_path(cwd: &Path) -> PathBuf {
            most_specific_config_write_target(cwd)
                .unwrap_or_else(|| cwd.join(".cockpit").join(CONFIG_FILE))
        }

        pub fn apply_security_answers(cwd: &Path, run: &WizardRun) -> Result<Option<PathBuf>> {
            let effective = cockpit_config::config::extended::load_for_cwd(cwd);
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
            let global_mode = cockpit_config::config::extended::load_for_cwd(cwd).llm_mode;
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
                provider
                    .models
                    .push(cockpit_config::config::providers::ModelEntry {
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

            let next_active = model_make_default_answer(run).then(|| {
                cockpit_config::config::providers::ActiveModelRef {
                    provider: provider_id.clone(),
                    model: model_id.clone(),
                    reasoning_effort: None,
                    thinking_mode: None,
                }
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
            current: CapabilityStatus,
            base: CapabilityStatus,
            existing: Option<CapabilityStatus>,
        ) -> Option<CapabilityStatus> {
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
    }
}
