use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::cli::{ConfigCommand, ConfigExportPolicyArgs, ConfigImportPolicyArgs};
use crate::config::extended::{DeepthinkConfig, ExtendedConfig, ExtendedConfigDoc};
use crate::config::providers::{HeaderSpec, ProviderEntry, ProvidersConfig};

const POLICY_BUNDLE_VERSION: u32 = 1;

pub async fn run(cmd: ConfigCommand) -> Result<()> {
    match cmd {
        ConfigCommand::ExportPolicy(args) => export_policy(args).await,
        ConfigCommand::ImportPolicy(args) => import_policy(args).await,
    }
}

async fn export_policy(args: ConfigExportPolicyArgs) -> Result<()> {
    let cwd = std::env::current_dir().context("resolving current directory")?;
    let bundle = build_policy_bundle(&cwd);
    let json = serde_json::to_string_pretty(&bundle).context("serializing policy bundle")?;
    match args.output {
        Some(path) => {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            std::fs::write(&path, format!("{json}\n"))
                .with_context(|| format!("writing {}", path.display()))?;
            println!("Exported portable policy bundle to {}", path.display());
        }
        None => println!("{json}"),
    }
    Ok(())
}

async fn import_policy(args: ConfigImportPolicyArgs) -> Result<()> {
    let raw = std::fs::read_to_string(&args.file)
        .with_context(|| format!("reading {}", args.file.display()))?;
    let bundle: PolicyBundle =
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", args.file.display()))?;
    anyhow::ensure!(
        bundle.version == POLICY_BUNDLE_VERSION,
        "unsupported policy bundle version {}; expected {}",
        bundle.version,
        POLICY_BUNDLE_VERSION
    );

    let cwd = std::env::current_dir().context("resolving current directory")?;
    let target = policy_write_target(&cwd)?;

    let mut provider_doc = crate::config::providers::ConfigDoc::load(&target)?;
    let providers =
        provider_policy_after_import(provider_doc.providers(), &bundle.providers, args.replace);
    provider_doc.write(&providers)?;

    let mut extended_doc = ExtendedConfigDoc::load(&target)?;
    let mut extended = if args.replace {
        ExtendedConfig::default()
    } else {
        extended_doc.config()
    };
    bundle.extended.apply_to(&mut extended);
    extended_doc.write(&extended)?;

    let mode = if args.replace { "replaced" } else { "merged" };
    println!(
        "Imported portable policy bundle into {} ({mode}; {} provider{}). Reconnect any credentials referenced by name on this machine.",
        target.display(),
        bundle.providers.providers.len(),
        if bundle.providers.providers.len() == 1 {
            ""
        } else {
            "s"
        }
    );
    Ok(())
}

fn build_policy_bundle(cwd: &Path) -> PolicyBundle {
    let mut providers = crate::secret_ref::load_effective(cwd);
    providers.active_model = None;
    sanitize_providers_for_portability(&mut providers);
    let extended = ExtendedConfigDoc::load(
        &crate::config::dirs::most_specific_config_write_target(cwd)
            .unwrap_or_else(|| cwd.join(".cockpit").join(crate::config::dirs::CONFIG_FILE)),
    )
    .map(|doc| PortableExtendedPolicy::from_config(&doc.config()))
    .unwrap_or_else(|_| {
        PortableExtendedPolicy::from_config(&crate::config::extended::load_for_cwd(cwd))
    });
    PolicyBundle {
        version: POLICY_BUNDLE_VERSION,
        providers,
        extended,
    }
}

fn policy_write_target(cwd: &Path) -> Result<PathBuf> {
    if let Some(path) = crate::config::dirs::most_specific_config_write_target(cwd) {
        return Ok(path);
    }
    let Some(dir) = crate::config::dirs::cwd_scoped_creatable_dirs(cwd)
        .into_iter()
        .next()
        .map(|d| d.path)
    else {
        anyhow::bail!(
            "no writable config layer is available for {}",
            cwd.display()
        );
    };
    Ok(dir.join(crate::config::dirs::CONFIG_FILE))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolicyBundle {
    version: u32,
    providers: ProvidersConfig,
    #[serde(default)]
    extended: PortableExtendedPolicy,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct PortableExtendedPolicy {
    #[serde(default, rename = "trustedOnly")]
    trusted_only: bool,
    #[serde(default)]
    deepthink: DeepthinkConfig,
    #[serde(default, skip_serializing_if = "is_false")]
    agent_chooses_subagent_model: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    utility_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    translation_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cheap_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    smart_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reasoning: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auto_title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    skill_injection: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    predict_next_message_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    harness_report_summarization: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    compact_model: Option<String>,
}

impl PortableExtendedPolicy {
    fn from_config(cfg: &ExtendedConfig) -> Self {
        Self {
            trusted_only: cfg.trusted_only,
            deepthink: cfg.deepthink.clone(),
            agent_chooses_subagent_model: cfg.agent_chooses_subagent_model,
            utility_model: cfg.utility_model.clone(),
            translation_model: cfg.translation_model.clone(),
            cheap_code: cfg.cheap_code.clone(),
            smart_code: cfg.smart_code.clone(),
            reasoning: cfg.reasoning.clone(),
            auto_title: cfg.auto_title.clone(),
            skill_injection: cfg.skill_injection.clone(),
            predict_next_message_model: cfg.predict_next_message_model.clone(),
            harness_report_summarization: cfg.harness_report_summarization.clone(),
            compact_model: cfg.compact_model.clone(),
        }
    }

    fn apply_to(&self, cfg: &mut ExtendedConfig) {
        cfg.trusted_only = self.trusted_only;
        cfg.deepthink = self.deepthink.clone();
        cfg.agent_chooses_subagent_model = self.agent_chooses_subagent_model;
        cfg.utility_model = self.utility_model.clone();
        cfg.translation_model = self.translation_model.clone();
        cfg.cheap_code = self.cheap_code.clone();
        cfg.smart_code = self.smart_code.clone();
        cfg.reasoning = self.reasoning.clone();
        cfg.auto_title = self.auto_title.clone();
        cfg.skill_injection = self.skill_injection.clone();
        cfg.predict_next_message_model = self.predict_next_message_model.clone();
        cfg.harness_report_summarization = self.harness_report_summarization.clone();
        cfg.compact_model = self.compact_model.clone();
    }
}

fn sanitize_providers_for_portability(cfg: &mut ProvidersConfig) {
    for entry in cfg.providers.values_mut() {
        entry.headers = portable_headers(&entry.headers);
        entry.last_model_fetch = None;
        entry.models_fetched_at = None;
    }
}

fn portable_headers(headers: &[HeaderSpec]) -> Vec<HeaderSpec> {
    headers
        .iter()
        .filter(|header| {
            !crate::envref::resolve_with(&header.value, |_| None)
                .referenced
                .is_empty()
        })
        .cloned()
        .collect()
}

fn merge_provider_policy(target: &mut ProvidersConfig, imported: &ProvidersConfig) {
    target.on_unlisted_models_fetch = imported.on_unlisted_models_fetch;
    target.category_defaults = imported.category_defaults.clone();
    for (id, incoming) in &imported.providers {
        match target.providers.get_mut(id) {
            Some(existing) => merge_provider_entry(existing, incoming),
            None => {
                target.providers.insert(id.clone(), incoming.clone());
            }
        }
    }
}

fn provider_policy_after_import(
    mut current: ProvidersConfig,
    imported: &ProvidersConfig,
    replace: bool,
) -> ProvidersConfig {
    let mut providers = if replace {
        imported.clone()
    } else {
        merge_provider_policy(&mut current, imported);
        current
    };
    providers.active_model = None;
    providers
}

fn merge_provider_entry(existing: &mut ProviderEntry, incoming: &ProviderEntry) {
    let local_headers = existing.headers.clone();
    let mut merged = incoming.clone();
    if merged.headers.is_empty() {
        merged.headers = local_headers;
    }
    merge_model_entries(&mut merged.models, &existing.models, &incoming.models);
    *existing = merged;
}

fn merge_model_entries(
    out: &mut Vec<crate::config::providers::ModelEntry>,
    existing: &[crate::config::providers::ModelEntry],
    incoming: &[crate::config::providers::ModelEntry],
) {
    let mut by_id: BTreeMap<String, crate::config::providers::ModelEntry> = existing
        .iter()
        .map(|model| (model.id.clone(), model.clone()))
        .collect();
    for model in incoming {
        by_id.insert(model.id.clone(), model.clone());
    }
    *out = by_id.into_values().collect();
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::providers::{ModelEntry, ModelLocation, ModelTrust, ProviderModelRef};

    fn provider(url: &str) -> ProviderEntry {
        ProviderEntry {
            url: url.to_string(),
            ..ProviderEntry::default()
        }
    }

    #[test]
    fn portable_headers_keep_env_refs_and_drop_literals() {
        let headers = portable_headers(&[
            HeaderSpec {
                name: "Authorization".into(),
                value: "Bearer sk-secret".into(),
            },
            HeaderSpec {
                name: "Authorization".into(),
                value: "Bearer $OPENAI_API_KEY".into(),
            },
        ]);
        assert_eq!(
            headers,
            vec![HeaderSpec {
                name: "Authorization".into(),
                value: "Bearer $OPENAI_API_KEY".into(),
            }]
        );
    }

    #[test]
    fn policy_bundle_omits_active_model_and_raw_secret_headers() {
        let mut cfg = ProvidersConfig::default();
        let mut entry = provider("https://api.example.test/v1");
        entry.headers.push(HeaderSpec {
            name: "Authorization".into(),
            value: "Bearer sk-secret".into(),
        });
        entry.trust = Some(ModelTrust::Trusted);
        cfg.active_model = Some(crate::config::providers::ActiveModelRef {
            provider: "p".into(),
            model: "m".into(),
            reasoning_effort: None,
            thinking_mode: None,
        });
        cfg.providers.insert("p".into(), entry);
        sanitize_providers_for_portability(&mut cfg);
        cfg.active_model = None;

        let json = serde_json::to_string(&cfg).unwrap();
        assert!(!json.contains("sk-secret"), "{json}");
        assert!(!json.contains("active_model"), "{json}");
        assert!(json.contains("\"trust\":\"trusted\""), "{json}");
    }

    #[test]
    fn merge_imported_policy_wins_but_empty_headers_preserve_local_secret_setup() {
        let mut target = ProvidersConfig::default();
        let mut local = provider("https://old.example.test/v1");
        local.headers.push(HeaderSpec {
            name: "Authorization".into(),
            value: "Bearer $LOCAL_TOKEN".into(),
        });
        local.models.push(ModelEntry {
            id: "old".into(),
            ..ModelEntry::default()
        });
        target.providers.insert("p".into(), local);

        let mut imported = ProvidersConfig::default();
        let mut incoming = provider("https://new.example.test/v1");
        incoming.trust = Some(ModelTrust::Trusted);
        incoming.location = Some(ModelLocation::PrivateRemote);
        incoming.quality_rank = Some(9);
        incoming.cost_rank = Some(2);
        incoming.subagent_invokable = Some(true);
        incoming.models.push(ModelEntry {
            id: "new".into(),
            trust: Some(ModelTrust::Untrusted),
            ..ModelEntry::default()
        });
        imported.providers.insert("p".into(), incoming);
        imported.category_defaults.insert(
            "cheap_code".into(),
            ProviderModelRef {
                provider: "p".into(),
                model: "new".into(),
            },
        );

        merge_provider_policy(&mut target, &imported);
        let merged = &target.providers["p"];
        assert_eq!(merged.url, "https://new.example.test/v1");
        assert_eq!(merged.headers[0].value, "Bearer $LOCAL_TOKEN");
        assert_eq!(merged.trust, Some(ModelTrust::Trusted));
        assert_eq!(merged.location, Some(ModelLocation::PrivateRemote));
        assert_eq!(merged.quality_rank, Some(9));
        assert_eq!(merged.cost_rank, Some(2));
        assert_eq!(merged.subagent_invokable, Some(true));
        assert!(merged.models.iter().any(|m| m.id == "old"));
        assert!(merged.models.iter().any(|m| m.id == "new"));
        assert_eq!(target.category_defaults["cheap_code"].model, "new");
    }

    #[test]
    fn replace_imported_policy_drops_local_providers_and_active_model() {
        let mut current = ProvidersConfig {
            active_model: Some(crate::config::providers::ActiveModelRef {
                provider: "local".into(),
                model: "old".into(),
                reasoning_effort: None,
                thinking_mode: None,
            }),
            ..Default::default()
        };
        current
            .providers
            .insert("local".into(), provider("https://local.example.test/v1"));

        let mut imported = ProvidersConfig {
            active_model: Some(crate::config::providers::ActiveModelRef {
                provider: "imported".into(),
                model: "new".into(),
                reasoning_effort: None,
                thinking_mode: None,
            }),
            ..Default::default()
        };
        imported.providers.insert(
            "imported".into(),
            provider("https://imported.example.test/v1"),
        );

        let replaced = provider_policy_after_import(current, &imported, true);
        assert!(replaced.active_model.is_none());
        assert!(!replaced.providers.contains_key("local"));
        assert!(replaced.providers.contains_key("imported"));
    }

    #[test]
    fn extended_policy_applies_trusted_only_and_deepthink() {
        let policy = PortableExtendedPolicy {
            trusted_only: true,
            deepthink: DeepthinkConfig { enabled: true },
            agent_chooses_subagent_model: true,
            utility_model: Some("p:u".into()),
            ..PortableExtendedPolicy::default()
        };
        let mut cfg = ExtendedConfig::default();
        policy.apply_to(&mut cfg);
        assert!(cfg.trusted_only);
        assert!(cfg.deepthink.enabled);
        assert!(cfg.agent_chooses_subagent_model);
        assert_eq!(cfg.utility_model.as_deref(), Some("p:u"));
    }
}
