//! Daemon-owned import/export of portable configuration policy.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::extended::{DeepthinkConfig, ExtendedConfig, ExtendedConfigDoc};
use crate::config::providers::{ConfigDoc, ProviderEntry, ProvidersConfig, ThinkingParams};

const POLICY_BUNDLE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolicyBundle {
    version: u32,
    providers: ProvidersConfig,
    #[serde(default)]
    extended: PortableExtendedPolicy,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PortableExtendedPolicy {
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

pub fn export(cwd: &Path) -> Result<String> {
    let mut providers = crate::secret_ref::load_effective(cwd);
    providers.active_model = None;
    sanitize_providers(&mut providers);
    let extended_path = crate::config::dirs::most_specific_existing_config_write_target(cwd)
        .unwrap_or_else(|| cwd.join(".cockpit").join(crate::config::dirs::CONFIG_FILE));
    let extended = ExtendedConfigDoc::load(&extended_path)
        .map(|doc| PortableExtendedPolicy::from_config(&doc.config()))
        .unwrap_or_else(|_| {
            PortableExtendedPolicy::from_config(&crate::config::extended::load_for_cwd(cwd))
        });
    serde_json::to_string_pretty(&PolicyBundle {
        version: POLICY_BUNDLE_VERSION,
        providers,
        extended,
    })
    .context("serializing portable policy bundle")
}

pub fn import(
    cwd: &Path,
    bundle_json: &str,
    replace: bool,
    vault: Option<Arc<crate::secure_key::SecretVault>>,
) -> Result<(PathBuf, u32)> {
    let bundle: PolicyBundle =
        serde_json::from_str(bundle_json).context("parsing policy bundle")?;
    anyhow::ensure!(
        bundle.version == POLICY_BUNDLE_VERSION,
        "unsupported policy bundle version {}; expected {}",
        bundle.version,
        POLICY_BUNDLE_VERSION
    );
    let target = policy_write_target(cwd)?;
    let mut current = ConfigDoc::load(&target)?;
    let mut providers = if replace {
        bundle.providers.clone()
    } else {
        provider_policy_after_import(current.providers(), &bundle.providers)
    };
    // A policy bundle's provider base URLs are arbitrary caller-supplied data
    // and can embed credentials in their user-info or query string (e.g.
    // `https://user:secret@p.example/v1?api_key=secret`). Nothing downstream
    // strips them, so a hand-crafted bundle would land an inline secret as
    // plaintext in the provider config. Run every imported provider URL through
    // the SAME sanitizer the export side and the redacted owner view use
    // (`redact_url_for_owner_view`), at this ingestion funnel, so no inline URL
    // secret can ever be persisted. This covers EVERY provider entry on BOTH
    // the replace and merge paths; an unparseable value fails closed to
    // `[redacted]`.
    sanitize_imported_provider_urls(&mut providers);
    // A policy bundle is arbitrary caller-supplied data. Persisting it directly
    // would bypass the secret-staging funnel (`PutNamedSecret` / vault-only
    // custody) that every other provider-save path funnels through, letting an
    // imported literal `Authorization: Bearer <key>` land as plaintext in the
    // provider config. Reject any imported provider header whose value is not a
    // structurally valid deferred reference — the exact rule the daemon
    // provider-save path enforces — before writing anything to disk.
    reject_literal_provider_credentials(&providers)?;
    // A policy bundle can also smuggle a plaintext secret through the OPAQUE,
    // free-form JSON fields on a provider entry (and its nested model entries):
    // `provider_metadata` / model `extra` are arbitrary `Map<String, Value>`
    // bags where a literal (e.g. `provider_metadata.auth.api_key`) can hide
    // anywhere. The URL sanitizer and the header reference gate above never
    // touch them, so a crafted bundle would land the literal as plaintext in
    // the provider config at `current.write`. Per the redaction contract
    // (guidance L8) an opaque blob cannot be selectively scrubbed — OMIT it.
    // Clear every such field on this import funnel before persisting.
    strip_opaque_provider_fields_in(&mut providers);
    // A structurally valid `$secret:NAME` reference can still name a secret owned
    // by a DIFFERENT kind (an MCP `mcp:` token) or a different workspace. The
    // header reference gate above only checks reference SHAPE, not OWNERSHIP.
    // Re-check AND claim every imported provider reference atomically under one
    // `BEGIN IMMEDIATE` writer transaction IMMEDIATELY before publishing the
    // config: a foreign/cross-kind name fails the whole import closed (nothing is
    // written), and a valid legacy/unclaimed name is claimed here so a concurrent
    // foreign claim cannot interpose between the check and the publish. The claim
    // keys on the canonical workspace root, matching later owner-scoped
    // resolution. Owner-scoped resolution (gap 1) remains a defense-in-depth
    // backstop.
    if let Some(vault) = vault.as_ref() {
        let canonical_root =
            crate::secret_ownership::canonical_owner_root(&cwd.display().to_string());
        claim_imported_provider_references(&providers, vault, &canonical_root)?;
    }
    current.write(&providers)?;

    let mut extended_doc = ExtendedConfigDoc::load(&target)?;
    let mut extended = if replace {
        ExtendedConfig::default()
    } else {
        extended_doc.config()
    };
    bundle.extended.apply_to(&mut extended);
    extended_doc.write(&extended)?;
    Ok((target, bundle.providers.providers.len() as u32))
}

/// Reject any provider header whose value is not a structurally valid deferred
/// reference (or safe public metadata). This is the same reference-only rule
/// `save_provider` / `upsert_provider_config_via_daemon` enforce, applied at the
/// import ingestion funnel so a literal credential can never be persisted into
/// the provider config by way of a policy bundle.
fn reject_literal_provider_credentials(providers: &ProvidersConfig) -> Result<()> {
    for (provider_id, entry) in &providers.providers {
        for header in &entry.headers {
            if !crate::config::providers::is_safe_provider_header_reference(
                &header.name.to_ascii_lowercase(),
                &header.value,
            ) {
                anyhow::bail!(
                    "imported provider `{provider_id}` header `{}` carries a literal credential; \
                     policy bundles may only reference secrets (e.g. `$secret:NAME` or `$ENV`)",
                    header.name
                );
            }
        }
    }
    Ok(())
}

/// Atomically re-check AND claim every imported provider `$secret:NAME`
/// reference for `(provider, project_root)` under one `BEGIN IMMEDIATE` writer
/// transaction, immediately before the config is published.
///
/// [`crate::secret_ownership::claim_named_reference_on_conn`] rejects any name
/// already owned by a foreign kind/workspace (the whole import rolls back with
/// no config written) and `INSERT OR IGNORE`s the claim for this workspace
/// otherwise — so a valid legacy/unclaimed name is durably claimed here and a
/// concurrent foreign claim cannot interpose between an earlier read-only check
/// and the publish. An already-same-owner reference is a no-op. `project_root`
/// must already be the canonical owner root.
fn claim_imported_provider_references(
    providers: &ProvidersConfig,
    vault: &crate::secure_key::SecretVault,
    project_root: &str,
) -> Result<()> {
    let names = crate::secret_ref::provider_named_secret_references(providers);
    if names.is_empty() {
        return Ok(());
    }
    let project_root = project_root.to_string();
    let names: Vec<String> = names.into_iter().collect();
    vault.db().blocking_write_for_sync_maintenance(move |conn| {
        conn.execute_batch("BEGIN IMMEDIATE;")?;
        let result = (|| -> anyhow::Result<()> {
            for name in &names {
                crate::secret_ownership::claim_named_reference_on_conn(
                    conn,
                    name,
                    crate::secret_ownership::OWNER_KIND_PROVIDER,
                    &project_root,
                )
                .map_err(|conflict| {
                    anyhow::anyhow!(
                        "imported provider references secret `{name}` owned by a different kind or workspace: {conflict}"
                    )
                })?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                conn.execute_batch("COMMIT;")?;
                Ok(())
            }
            Err(error) => {
                let _ = conn.execute_batch("ROLLBACK;");
                Err(error)
            }
        }
    })
}

/// Strip credential-bearing components (user-info, query string, fragment)
/// from every imported provider base URL, reusing the exact export-side
/// sanitizer. Applied at the import ingestion funnel so no policy-bundle path
/// (replace or merge) can persist an inline URL secret. An unparseable URL is
/// reduced to `[redacted]` (fail closed).
fn sanitize_imported_provider_urls(providers: &mut ProvidersConfig) {
    for entry in providers.providers.values_mut() {
        entry.url = crate::daemon::proto::redact_url_for_owner_view(&entry.url);
    }
}

fn policy_write_target(cwd: &Path) -> Result<PathBuf> {
    // Workspace-bound: import into a discovered layer, else the cwd-scoped
    // creatable dirs (project `.cockpit/` then machine-local). Never the
    // user-level global fallback — a fresh-install import must not become
    // every project's default policy.
    if let Some(path) = crate::config::dirs::most_specific_existing_config_write_target(cwd) {
        return Ok(path);
    }
    let dir = crate::config::dirs::cwd_scoped_creatable_dirs(cwd)
        .into_iter()
        .next()
        .map(|d| d.path)
        .context("no writable config layer is available")?;
    Ok(dir.join(crate::config::dirs::CONFIG_FILE))
}

fn sanitize_providers(cfg: &mut ProvidersConfig) {
    for entry in cfg.providers.values_mut() {
        // A base URL can embed credentials in its user-info or query string
        // (e.g. `https://p.example/v1?api_key=SECRET`). Strip those structurally
        // before serialization so no inline secret survives into the bundle,
        // reusing the same owner-view sanitizer the redacted provider projection
        // uses. An unparseable URL is reduced to `[redacted]` (fail closed).
        entry.url = crate::daemon::proto::redact_url_for_owner_view(&entry.url);
        // Retain a header ONLY when its whole value is a structurally valid
        // deferred reference (or safe public metadata) per the same guard the
        // provider-save path enforces. A value that merely *contains* a
        // reference (e.g. `Bearer $API_TOKEN literal-secret`) is NOT safe: the
        // inline literal suffix is an unknown secret the global redaction table
        // cannot mask, so it would leak whole into the exported bundle. Drop
        // any header that is not a safe reference rather than emitting its raw
        // value.
        entry.headers.retain(|header| {
            crate::config::providers::is_safe_provider_header_reference(
                &header.name.to_ascii_lowercase(),
                &header.value,
            )
        });
        entry.last_model_fetch = None;
        entry.models_fetched_at = None;
        // Same opaque-blob class as the import funnel: `provider_metadata` and
        // model `extra`/`provider_metadata` are free-form JSON where a secret
        // can hide anywhere and cannot be selectively scrubbed (guidance L8).
        // Omit them so an export cannot leak a plaintext secret a provider file
        // happened to carry in one of these un-validated bags.
        strip_opaque_provider_fields(entry);
    }
}

/// Clear every OPAQUE, free-form JSON field on a provider entry and its nested
/// model entries. These bags (`ProviderEntry::provider_metadata` and
/// `thinking_params`, and each `ModelEntry`'s `extra`, `provider_metadata`, and
/// `thinking_params`) accept arbitrary `Value` content — the `thinking_params`
/// keys are a closed `ThinkingMode` enum but the values are unconstrained JSON,
/// so a literal secret can hide anywhere inside any of them and cannot be
/// selectively scrubbed — per the redaction contract (guidance L8) an opaque
/// blob must be OMITTED. Every OTHER field that could
/// carry a caller-supplied secret is a typed, single-purpose channel handled
/// elsewhere: `url` is structurally sanitized, `headers` are gated to
/// reference-only values, `credential_ref` is a pointer, and `auth` is a closed
/// enum. The remaining strings (`name`, model `system_prompt`) are
/// intentionally user-authored display/prompt text, not free-form JSON secret
/// sinks, so they are preserved.
fn strip_opaque_provider_fields(entry: &mut ProviderEntry) {
    entry.provider_metadata.clear();
    entry.thinking_params = ThinkingParams::default();
    for model in &mut entry.models {
        model.provider_metadata.clear();
        model.extra.clear();
        model.thinking_params = ThinkingParams::default();
    }
}

/// Apply [`strip_opaque_provider_fields`] to every entry in an imported
/// provider config, at the import ingestion funnel, before it is persisted.
fn strip_opaque_provider_fields_in(providers: &mut ProvidersConfig) {
    for entry in providers.providers.values_mut() {
        strip_opaque_provider_fields(entry);
    }
}

fn provider_policy_after_import(
    mut current: ProvidersConfig,
    imported: &ProvidersConfig,
) -> ProvidersConfig {
    current.on_unlisted_models_fetch = imported.on_unlisted_models_fetch;
    current.category_defaults = imported.category_defaults.clone();
    for (id, incoming) in &imported.providers {
        match current.providers.get_mut(id) {
            Some(existing) => merge_provider_entry(existing, incoming),
            None => {
                current.providers.insert(id.clone(), incoming.clone());
            }
        }
    }
    current.active_model = None;
    current
}

fn merge_provider_entry(existing: &mut ProviderEntry, incoming: &ProviderEntry) {
    let local_headers = existing.headers.clone();
    let mut merged = incoming.clone();
    if merged.headers.is_empty() {
        merged.headers = local_headers;
    }
    let mut by_id: BTreeMap<String, crate::config::providers::ModelEntry> = existing
        .models
        .iter()
        .map(|m| (m.id.clone(), m.clone()))
        .collect();
    for model in &incoming.models {
        by_id.insert(model.id.clone(), model.clone());
    }
    merged.models = by_id.into_values().collect();
    *existing = merged;
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_install_policy_write_target_is_cwd_scoped_not_global() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let cwd = tmp.path().join("work");
        std::fs::create_dir_all(&cwd).unwrap();
        let global = crate::config::dirs::global_config_file().unwrap();
        assert!(
            !global.parent().unwrap().is_dir(),
            "fresh-install fixture must not pre-create the global layer"
        );
        let target = policy_write_target(&cwd).unwrap();
        assert_ne!(
            target, global,
            "workspace-bound policy import must not fall back to the missing global layer"
        );
        assert!(
            target.starts_with(&cwd) || target.to_string_lossy().contains("local-configs"),
            "fresh-install policy target must be project or machine-local: {}",
            target.display()
        );
    }

    /// A secret embedded inline in a provider base URL (user-info or query
    /// string) must not survive into the exported policy bundle. This drives
    /// the real `export` entry point over an on-disk provider config so a
    /// regression that removes URL sanitization from `sanitize_providers`
    /// re-leaks the planted secret and fails the test.
    #[test]
    fn export_strips_secret_embedded_in_provider_url() {
        let tmp = tempfile::tempdir().unwrap();
        let env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let config_path = tmp.path().join("config.json");
        std::fs::write(&config_path, "{}\n").unwrap();
        env.set_cockpit_config(&config_path);

        let secret = "UNIQUE-URL-SECRET-9f3a1c7b";
        let provider_id = "custom";
        let provider_path =
            crate::config::providers::provider_file_path_for_config(&config_path, provider_id)
                .unwrap();
        std::fs::create_dir_all(provider_path.parent().unwrap()).unwrap();
        let raw = serde_json::json!({
            "url": format!("https://user:{secret}@p.example/v1?api_key={secret}"),
        });
        std::fs::write(&provider_path, serde_json::to_string_pretty(&raw).unwrap()).unwrap();

        // Precondition: the planted secret really is on disk in the config the
        // exporter is about to read (otherwise the test could pass vacuously).
        let on_disk = std::fs::read_to_string(&provider_path).unwrap();
        assert!(
            on_disk.contains(secret),
            "planted secret must be present in the on-disk provider config"
        );

        let bundle = export(tmp.path()).expect("export policy bundle");

        // Non-vacuity: the provider survived the load (its sanitized host is in
        // the bundle), so absence of the secret is real sanitization, not a
        // dropped provider.
        assert!(
            bundle.contains("p.example"),
            "provider must be present in the exported bundle:\n{bundle}"
        );
        assert!(
            !bundle.contains(secret),
            "exported bundle leaked a URL-embedded secret:\n{bundle}"
        );
    }

    /// A header value that merely *contains* a recognized reference but also
    /// carries an inline literal suffix (e.g. `Bearer $API_TOKEN literal`) is
    /// NOT a safe whole reference: the literal suffix is an unknown secret the
    /// global redaction table cannot mask, so it must not survive into the
    /// exported bundle. This drives the real `export` entry point over an
    /// on-disk provider config; the pre-fix `retain(referenced non-empty)`
    /// logic kept these mixed values whole and leaked the suffixes.
    #[test]
    fn export_drops_header_with_reference_plus_inline_literal_suffix() {
        let tmp = tempfile::tempdir().unwrap();
        let env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let config_path = tmp.path().join("config.json");
        std::fs::write(&config_path, "{}\n").unwrap();
        env.set_cockpit_config(&config_path);

        let env_suffix = "ENVLEAK-9a1b2c3d";
        let secret_suffix = "SECRETLEAK-7e6f5a4b";
        let provider_id = "custom";
        let provider_path =
            crate::config::providers::provider_file_path_for_config(&config_path, provider_id)
                .unwrap();
        std::fs::create_dir_all(provider_path.parent().unwrap()).unwrap();
        let raw = serde_json::json!({
            "url": "https://p.example/v1",
            "headers": [
                // `$API_TOKEN` is a recognized reference, but the trailing
                // `literal` bytes are an inline secret. A mixed value like this
                // is not a structurally valid whole reference.
                {"name": "Authorization", "value": format!("Bearer $API_TOKEN {env_suffix}")},
                // A `$secret:` reference followed by an inline literal suffix.
                {"name": "X-Api-Key", "value": format!("$secret:realname {secret_suffix}")},
                // A clean, whole reference that MUST be retained, so the test
                // proves the drop is specific to unsafe values and not a blanket
                // "strip all headers".
                {"name": "X-Clean", "value": "$CLEAN_TOKEN"},
            ],
        });
        std::fs::write(&provider_path, serde_json::to_string_pretty(&raw).unwrap()).unwrap();

        // Precondition: the planted inline literals really are on disk in the
        // form the exporter reads.
        let on_disk = std::fs::read_to_string(&provider_path).unwrap();
        assert!(
            on_disk.contains(env_suffix) && on_disk.contains(secret_suffix),
            "planted inline literal suffixes must be present on disk"
        );

        let bundle = export(tmp.path()).expect("export policy bundle");

        // Non-vacuity: the provider survived the load and its clean whole
        // reference is retained, so absence of the suffixes is real filtering,
        // not a dropped provider or blanket header strip.
        assert!(
            bundle.contains("p.example"),
            "provider must be present in the exported bundle:\n{bundle}"
        );
        assert!(
            bundle.contains("$CLEAN_TOKEN"),
            "a clean whole reference must be retained:\n{bundle}"
        );
        assert!(
            !bundle.contains(env_suffix),
            "exported bundle leaked an inline env-ref literal suffix:\n{bundle}"
        );
        assert!(
            !bundle.contains(secret_suffix),
            "exported bundle leaked an inline $secret literal suffix:\n{bundle}"
        );
    }

    /// Importing a policy bundle must not bypass the secret-staging funnel: a
    /// literal credential header in the bundle must be rejected before anything
    /// is written to the provider config on disk. Drives the real `import`
    /// entry point; the pre-fix path wrote the literal straight to config.
    #[test]
    fn import_rejects_literal_credential_header_and_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let config_path = tmp.path().join("config.json");
        std::fs::write(&config_path, "{}\n").unwrap();
        env.set_cockpit_config(&config_path);

        let literal_key = "LITERAL-APIKEY-3c2b1a09";
        let bundle = serde_json::json!({
            "version": POLICY_BUNDLE_VERSION,
            "providers": {
                "providers": {
                    "custom": {
                        "url": "https://p.example/v1",
                        "headers": [
                            {"name": "Authorization", "value": format!("Bearer {literal_key}")},
                        ],
                    }
                }
            }
        });
        let bundle_json = serde_json::to_string(&bundle).unwrap();

        let error = import(tmp.path(), &bundle_json, false, None)
            .expect_err("import must reject a literal credential header");
        assert!(
            error.to_string().contains("literal credential"),
            "rejection must be the literal-credential guard, not an unrelated error: {error:#}"
        );

        // Fail-closed: nothing containing the literal may have been persisted to
        // any config file under the isolated home.
        let target = policy_write_target(tmp.path()).unwrap();
        if let Ok(written) = std::fs::read_to_string(&target) {
            assert!(
                !written.contains(literal_key),
                "import persisted a literal credential into the config:\n{written}"
            );
        }
    }

    /// A structurally valid `$secret:NAME` reference can still name a secret owned
    /// by a different kind/workspace. The import path must reject such a bundle
    /// (fail fast) rather than making a provider consume a foreign-owned vault
    /// value. Drives the real `import` entry point with a daemon vault whose
    /// ownership table already attributes `shared` to a FOREIGN workspace, and
    /// asserts the import fails closed and writes nothing referencing the name.
    #[test]
    fn import_rejects_provider_reference_owned_by_foreign_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let config_path = tmp.path().join("config.json");
        std::fs::write(&config_path, "{}\n").unwrap();
        env.set_cockpit_config(&config_path);

        let db = crate::db::Db::open_in_memory().unwrap();
        let vault = crate::secure_key::open_for_db(&db).unwrap();
        // `shared` is owned by a DIFFERENT workspace (foreign to this import cwd).
        db.blocking_write_for_sync_maintenance(|conn| {
            conn.execute(
                "INSERT INTO secret_named_ownership (item_id, owner_kind, project_root, created_at)
                 VALUES ('shared', 'provider', '/foreign/workspace', 0)",
                [],
            )?;
            Ok(())
        })
        .unwrap();

        let bundle = serde_json::json!({
            "version": POLICY_BUNDLE_VERSION,
            "providers": {
                "providers": {
                    "custom": {
                        "url": "https://p.example/v1",
                        "headers": [
                            {"name": "Authorization", "value": "$secret:shared"},
                        ],
                    }
                }
            }
        });
        let bundle_json = serde_json::to_string(&bundle).unwrap();

        // Precondition: the bundle's reference is SHAPE-valid — `$secret:shared`
        // passes the literal-credential gate — so the rejection below is the
        // ownership guard, not an unrelated shape error. (Only ONE TestEnvGuard may
        // be alive at a time; the global lock is held for this whole test, so we
        // cannot spin up a second isolated home — instead we assert directly that
        // the shape gate accepts the reference and the ownership guard is what
        // rejects.)
        assert!(
            reject_literal_provider_credentials(&{
                let mut p = ProvidersConfig::default();
                p.providers.insert(
                    "custom".to_string(),
                    ProviderEntry {
                        url: "https://p.example/v1".to_string(),
                        headers: vec![crate::config::providers::HeaderSpec {
                            name: "Authorization".to_string(),
                            value: "$secret:shared".to_string(),
                        }],
                        ..Default::default()
                    },
                );
                p
            })
            .is_ok(),
            "precondition: `$secret:shared` is a shape-valid reference"
        );

        let error = import(tmp.path(), &bundle_json, false, Some(vault))
            .expect_err("import must reject a foreign-owned provider reference");
        assert!(
            error
                .to_string()
                .contains("owned by a different kind or workspace"),
            "rejection must be the ownership guard, not an unrelated error: {error:#}"
        );
        assert!(
            error.to_string().contains("shared"),
            "rejection must name the foreign-owned reference: {error:#}"
        );

        // Fail-closed: nothing referencing `shared` may have been persisted.
        let target = policy_write_target(tmp.path()).unwrap();
        if let Ok(written) = std::fs::read_to_string(&target) {
            assert!(
                !written.contains("$secret:shared"),
                "import persisted a foreign-owned reference into the config:\n{written}"
            );
        }
    }

    // Gap 6: import atomically CLAIMS a valid unclaimed provider reference for
    // this workspace (immediately before publishing the config), so a concurrent
    // foreign claim cannot interpose between the check and the publish. The old
    // read-only reject left the name unclaimed.
    #[test]
    fn import_claims_unclaimed_provider_reference() {
        let tmp = tempfile::tempdir().unwrap();
        let env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let config_path = tmp.path().join("config.json");
        std::fs::write(&config_path, "{}\n").unwrap();
        env.set_cockpit_config(&config_path);

        let db = crate::db::Db::open_in_memory().unwrap();
        let vault = crate::secure_key::open_for_db(&db).unwrap();

        let bundle = serde_json::json!({
            "version": POLICY_BUNDLE_VERSION,
            "providers": {
                "providers": {
                    "custom": {
                        "url": "https://p.example/v1",
                        "headers": [
                            {"name": "Authorization", "value": "$secret:fresh"},
                        ],
                    }
                }
            }
        });
        let bundle_json = serde_json::to_string(&bundle).unwrap();

        // Import succeeds AND publishes (the count reflects the imported provider).
        let (_target, count) = import(tmp.path(), &bundle_json, false, Some(vault))
            .expect("import of an unclaimed reference must succeed");
        assert_eq!(count, 1, "the provider must be published");

        // The reference is now durably CLAIMED for (provider, this canonical root).
        // The pre-fix read-only check left it UNCLAIMED (owned == 0); the atomic
        // recheck-and-claim before publish is what makes this 1.
        let canonical =
            crate::secret_ownership::canonical_owner_root(&tmp.path().display().to_string());
        let owned: i64 = db
            .blocking_read_for_sync_ui(move |conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM secret_named_ownership
                     WHERE item_id = 'fresh' AND owner_kind = 'provider' AND project_root = ?1",
                    rusqlite::params![canonical],
                    |row| row.get::<_, i64>(0),
                )?)
            })
            .unwrap();
        assert_eq!(owned, 1, "import must claim the unclaimed reference");
    }

    /// A hand-crafted policy bundle whose provider base URL embeds a credential
    /// in its user-info AND query string must not persist that secret into the
    /// provider config. Nothing else in the import path stripped the URL, so the
    /// pre-fix code wrote `https://user:secret@p.example/v1?api_key=secret`
    /// verbatim to disk. Drives the real `import` entry point and asserts the
    /// secret is absent from the written config while the provider survives.
    #[test]
    fn import_strips_secret_embedded_in_provider_url_before_persisting() {
        let tmp = tempfile::tempdir().unwrap();
        let env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let config_path = tmp.path().join("config.json");
        std::fs::write(&config_path, "{}\n").unwrap();
        env.set_cockpit_config(&config_path);

        let secret = "IMPORT-URL-SECRET-4d5e6f7a";
        let bundle = serde_json::json!({
            "version": POLICY_BUNDLE_VERSION,
            "providers": {
                "providers": {
                    "custom": {
                        "url": format!("https://user:{secret}@p.example/v1?api_key={secret}"),
                    }
                }
            }
        });
        let bundle_json = serde_json::to_string(&bundle).unwrap();

        // Precondition: the crafted bundle really carries the secret in the URL
        // (otherwise the test could pass vacuously).
        assert!(
            bundle_json.contains(secret),
            "crafted bundle must embed the secret in the provider URL"
        );

        // Both the replace and merge import paths must sanitize the URL.
        // Providers persist to per-provider sidecar files (not the returned
        // config target), so scan EVERY file the import wrote under the
        // isolated home to prove the sanitized provider landed and the secret
        // did not, wherever the daemon chose to store it.
        for replace in [true, false] {
            let (_target, count) =
                import(tmp.path(), &bundle_json, replace, None).expect("import policy bundle");
            assert_eq!(
                count, 1,
                "the crafted provider must be imported (replace={replace})"
            );
            let written = read_all_files_concatenated(tmp.path());
            // Non-vacuity: the provider survived the import (its host is on
            // disk), so absence of the secret is real sanitization, not a
            // dropped provider.
            assert!(
                written.contains("p.example"),
                "provider must be present on disk after import (replace={replace}):\n{written}"
            );
            assert!(
                !written.contains(secret),
                "import persisted a URL-embedded secret (replace={replace}):\n{written}"
            );
        }
    }

    /// Concatenate the contents of every regular file under `root` (recursively)
    /// so a test can assert over everything an operation wrote, regardless of
    /// which sidecar file the daemon chose.
    fn read_all_files_concatenated(root: &Path) -> String {
        fn visit(dir: &Path, out: &mut String) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    visit(&path, out);
                } else if let Ok(contents) = std::fs::read_to_string(&path) {
                    out.push_str(&contents);
                    out.push('\n');
                }
            }
        }
        let mut out = String::new();
        visit(root, &mut out);
        out
    }

    /// A hand-crafted policy bundle can nest a literal secret inside a
    /// provider's opaque, free-form `provider_metadata` bag (and inside a nested
    /// model's `extra` / `provider_metadata`). The URL sanitizer and the header
    /// reference gate never inspect these arbitrary-JSON bags, so the pre-fix
    /// import wrote the planted literal straight to the provider config. Per the
    /// redaction contract (guidance L8) an opaque blob is OMITTED, not scrubbed.
    /// This drives the real `import` entry point on BOTH the replace and merge
    /// paths and asserts the secret is absent from every file the import wrote
    /// while the provider itself survives.
    #[test]
    fn import_omits_opaque_provider_and_model_metadata_before_persisting() {
        let tmp = tempfile::tempdir().unwrap();
        let env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let config_path = tmp.path().join("config.json");
        std::fs::write(&config_path, "{}\n").unwrap();
        env.set_cockpit_config(&config_path);

        let provider_secret = "OPAQUE-PROVIDER-META-SECRET-8b2c1a9f";
        let model_meta_secret = "OPAQUE-MODEL-META-SECRET-4e7d0c3a";
        let model_extra_secret = "OPAQUE-MODEL-EXTRA-SECRET-1f6b5d2e";
        // `thinking_params` values are arbitrary JSON (only the mode keys are a
        // closed enum), so a credential can hide inside them at BOTH levels.
        let provider_thinking_secret = "OPAQUE-PROVIDER-THINKING-SECRET-3a5c7e9d";
        let model_thinking_secret = "OPAQUE-MODEL-THINKING-SECRET-6b8d0f2a";
        // A benign, typed, user-authored field that MUST survive the strip so
        // the omission of the opaque bags is proven selective, not a wipe.
        let benign_survivor = "BENIGN-DISPLAY-NAME-SURVIVES-5e1a3c7f";
        let bundle = serde_json::json!({
            "version": POLICY_BUNDLE_VERSION,
            "providers": {
                "providers": {
                    "custom": {
                        "url": "https://p.example/v1",
                        // Typed display text: preserved by the strip.
                        "name": benign_survivor,
                        // Opaque provider-level bag hides a literal credential.
                        "provider_metadata": { "auth": { "api_key": provider_secret } },
                        // Opaque provider-level thinking_params value bag.
                        "thinking_params": { "high": { "api_key": provider_thinking_secret } },
                        "models": [
                            {
                                "id": "m1",
                                // Opaque model-level bags hide literals too.
                                "provider_metadata": { "nested": { "token": model_meta_secret } },
                                "extra": { "leak": model_extra_secret },
                                // Opaque model-level thinking_params value bag.
                                "thinking_params": { "high": { "token": model_thinking_secret } }
                            }
                        ]
                    }
                }
            }
        });
        let bundle_json = serde_json::to_string(&bundle).unwrap();

        // Precondition: the crafted bundle really carries every planted secret
        // and the benign survivor (otherwise the test could pass vacuously).
        for secret in [
            provider_secret,
            model_meta_secret,
            model_extra_secret,
            provider_thinking_secret,
            model_thinking_secret,
            benign_survivor,
        ] {
            assert!(
                bundle_json.contains(secret),
                "crafted bundle must embed the planted value `{secret}`"
            );
        }

        for replace in [true, false] {
            let (_target, count) =
                import(tmp.path(), &bundle_json, replace, None).expect("import policy bundle");
            assert_eq!(
                count, 1,
                "the crafted provider must be imported (replace={replace})"
            );
            let written = read_all_files_concatenated(tmp.path());
            // Non-vacuity: the provider (and its model) survived the import, so
            // the absence of the secrets is real omission, not a dropped entry.
            assert!(
                written.contains("p.example"),
                "provider must be present on disk after import (replace={replace}):\n{written}"
            );
            assert!(
                written.contains("m1"),
                "model must be present on disk after import (replace={replace}):\n{written}"
            );
            // Selective omission: the benign typed display field survives.
            assert!(
                written.contains(benign_survivor),
                "benign typed field must survive the import strip (replace={replace}):\n{written}"
            );
            for secret in [
                provider_secret,
                model_meta_secret,
                model_extra_secret,
                provider_thinking_secret,
                model_thinking_secret,
            ] {
                assert!(
                    !written.contains(secret),
                    "import persisted an opaque-metadata secret `{secret}` (replace={replace}):\n{written}"
                );
            }
        }
    }

    /// The export side is symmetric: a provider file on disk that carries a
    /// secret in its opaque `provider_metadata` (or a model's `extra` /
    /// `provider_metadata`) must not leak it into the exported bundle. Drives
    /// the real `export` entry point over an on-disk provider config; the
    /// pre-fix `sanitize_providers` copied these bags through verbatim.
    #[test]
    fn export_omits_opaque_provider_and_model_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let config_path = tmp.path().join("config.json");
        std::fs::write(&config_path, "{}\n").unwrap();
        env.set_cockpit_config(&config_path);

        let provider_secret = "EXPORT-PROVIDER-META-SECRET-7c3e9a1b";
        let model_extra_secret = "EXPORT-MODEL-EXTRA-SECRET-2d8f4b6c";
        // `thinking_params` values are arbitrary JSON at both levels.
        let provider_thinking_secret = "EXPORT-PROVIDER-THINKING-SECRET-9f1b3d5a";
        let model_thinking_secret = "EXPORT-MODEL-THINKING-SECRET-4c6e8a0b";
        // A benign, typed, user-authored field that MUST survive the export.
        let benign_survivor = "EXPORT-BENIGN-DISPLAY-NAME-2b4d6f8a";
        let provider_id = "custom";
        let provider_path =
            crate::config::providers::provider_file_path_for_config(&config_path, provider_id)
                .unwrap();
        std::fs::create_dir_all(provider_path.parent().unwrap()).unwrap();
        let raw = serde_json::json!({
            "url": "https://p.example/v1",
            "name": benign_survivor,
            "provider_metadata": { "auth": { "api_key": provider_secret } },
            "thinking_params": { "high": { "api_key": provider_thinking_secret } },
            "models": [ {
                "id": "m1",
                "extra": { "leak": model_extra_secret },
                "thinking_params": { "high": { "token": model_thinking_secret } }
            } ],
        });
        std::fs::write(&provider_path, serde_json::to_string_pretty(&raw).unwrap()).unwrap();

        // Precondition: the planted secrets really are on disk in the config the
        // exporter is about to read.
        let on_disk = std::fs::read_to_string(&provider_path).unwrap();
        assert!(
            on_disk.contains(provider_secret)
                && on_disk.contains(model_extra_secret)
                && on_disk.contains(provider_thinking_secret)
                && on_disk.contains(model_thinking_secret)
                && on_disk.contains(benign_survivor),
            "planted values must be present on disk"
        );

        let bundle = export(tmp.path()).expect("export policy bundle");

        // Non-vacuity: the provider survived the load (its host is in the
        // bundle), so absence of the secrets is real omission, not a drop.
        assert!(
            bundle.contains("p.example"),
            "provider must be present in the exported bundle:\n{bundle}"
        );
        // Selective omission: the benign typed display field survives.
        assert!(
            bundle.contains(benign_survivor),
            "benign typed field must survive the export strip:\n{bundle}"
        );
        assert!(
            !bundle.contains(provider_secret),
            "exported bundle leaked an opaque provider_metadata secret:\n{bundle}"
        );
        assert!(
            !bundle.contains(model_extra_secret),
            "exported bundle leaked an opaque model extra secret:\n{bundle}"
        );
        assert!(
            !bundle.contains(provider_thinking_secret),
            "exported bundle leaked an opaque provider thinking_params secret:\n{bundle}"
        );
        assert!(
            !bundle.contains(model_thinking_secret),
            "exported bundle leaked an opaque model thinking_params secret:\n{bundle}"
        );
    }
}
