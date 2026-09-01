//! `$secret:<name>` storage, literal-header protection, and one-time migration.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};
use serde_json::Value;

use crate::config::providers::{ConfigDoc, ProviderEntry, ProvidersConfig};
use crate::credentials::CredentialStore;

static MIGRATED_LAYERS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRefNotice {
    pub migrated: usize,
    pub store_path: PathBuf,
}

impl SecretRefNotice {
    pub fn render(&self) -> String {
        let noun = if self.migrated == 1 {
            "provider secret"
        } else {
            "provider secrets"
        };
        format!(
            "Stored {} {noun} in {}; provider config now contains $secret: references.",
            self.migrated,
            crate::welcome::display_path(&self.store_path)
        )
    }
}

/// Every named-secret id (`$secret:NAME`) referenced by any provider header in
/// this config. Used to scope owner-scoped resolution (`owner_kind = provider`)
/// so legacy backfill only ever claims names the provider config actually uses.
pub fn provider_named_secret_references(
    providers: &ProvidersConfig,
) -> std::collections::BTreeSet<String> {
    providers
        .providers
        .values()
        .flat_map(provider_reference_strings)
        .flat_map(crate::envref::referenced_names)
        .filter_map(|name| name.strip_prefix("secret:").map(str::to_string))
        .collect()
}

/// Every named-secret id (`$secret:NAME`) referenced by the headers of ONLY the
/// `provider_id` entry. Scoped to a single provider so a credentials failure on
/// one provider re-resolves that provider's command secret(s) and never a
/// sibling provider's (same-workspace). Empty when the provider is absent or
/// references no `$secret:` names.
pub fn provider_named_secret_references_for(
    providers: &ProvidersConfig,
    provider_id: &str,
) -> std::collections::BTreeSet<String> {
    providers
        .providers
        .get(provider_id)
        .into_iter()
        .flat_map(provider_reference_strings)
        .flat_map(crate::envref::referenced_names)
        .filter_map(|name| name.strip_prefix("secret:").map(str::to_string))
        .collect()
}

fn provider_reference_strings(entry: &ProviderEntry) -> impl Iterator<Item = &str> {
    entry
        .headers
        .iter()
        .map(|header| header.value.as_str())
        .chain(entry.auth_command.iter().flatten().map(String::as_str))
}

/// CLI-owned effective provider loader. The config crate keeps header values
/// opaque; this boundary performs the credential-store migration before the
/// values can be used by request construction.
pub fn load_effective(cwd: &Path) -> ProvidersConfig {
    try_load_effective(cwd).unwrap_or_else(|error| {
        // Infallible callers still must not observe a half-committed default;
        // the degraded resolution drops the pending layer's `active_model`.
        tracing::error!(%error, "serving a degraded effective provider config");
        let paths = crate::config::dirs::config_file_paths_for_load(cwd);
        ConfigDoc::load_effective_from_paths(&paths)
    })
}

/// Fallible variant for daemon-facing loads.
///
/// Fails closed when a configuration layer has a pending default-model
/// transaction that can neither be recovered nor masked, so attach reports a
/// typed error rather than serving a snapshot that might disagree with the
/// session's durable model.
pub fn try_load_effective(cwd: &Path) -> anyhow::Result<ProvidersConfig> {
    prepare_effective_layers(cwd);
    let paths = crate::config::dirs::config_file_paths_for_load(cwd);
    ConfigDoc::try_load_effective_from_paths(&paths)
}

/// Complete the best-effort provider credential migration before another
/// subsystem captures configuration layers for an effective resolution.
pub(crate) fn prepare_effective_layers(cwd: &Path) {
    let _ = prepare_effective_layers_with_store(cwd, None);
}

pub(crate) fn prepare_effective_layers_with_store(
    cwd: &Path,
    mut store: Option<CredentialStore>,
) -> Result<()> {
    migrate_effective_layers_once_with_store(cwd, store.as_mut())
}

/// Project a resolved [`ProvidersConfig`] to the redacted view the daemon
/// pushes to clients (`tui-config-single-source`). Credential refs and header
/// *values* are stripped; header *names* and a `credential_configured` flag are
/// retained so the client can render provider state without ever seeing secret
/// material. The daemon and the TUI's pre-attach bootstrap share this one
/// projection so their views are byte-identical for the same config tree.
pub fn redact_provider_view(
    providers: &ProvidersConfig,
) -> crate::daemon::proto::ProviderConfigView {
    use crate::daemon::proto;
    proto::ProviderConfigView {
        providers: providers
            .providers
            .iter()
            .map(|(id, entry)| {
                let credential_configured = entry.credential_ref.is_some()
                    || !entry.headers.is_empty()
                    || entry.auth_command.is_some();
                let headers = entry
                    .headers
                    .iter()
                    .map(|header| proto::ProviderHeaderView {
                        name: header.name.clone(),
                        value: "[redacted]".to_string(),
                        redacted: true,
                    })
                    .collect();
                let mut entry = entry.clone();
                // URLs are generally safe configuration metadata, but users
                // and providers do put credentials in query/user-info.  This
                // view is owner-remoted, so never echo either component.
                entry.url = proto::redact_url_for_owner_view(&entry.url);
                entry.credential_ref = None;
                entry.headers.clear();
                entry.auth_command = None;
                (
                    id.clone(),
                    proto::ProviderEntryView {
                        entry,
                        headers,
                        credential_configured,
                    },
                )
            })
            .collect(),
        category_defaults: providers.category_defaults.clone(),
        on_unlisted_models_fetch: providers.on_unlisted_models_fetch,
        active_model: providers.active_model.clone(),
        mcp_config_json: None,
        mcp_authored_config_json: None,
        mcp_owner_root: None,
        mcp_config_path: None,
        mcp_edit_capability: None,
        mcp_revision: None,
        mcp_scope_revisions: Default::default(),
        extended_config_json: None,
    }
}

#[allow(dead_code)]
fn migrate_effective_layers_once(cwd: &Path) -> Result<()> {
    migrate_effective_layers_once_with_store(cwd, None)
}

fn migrate_effective_layers_once_with_store(
    cwd: &Path,
    store: Option<&mut CredentialStore>,
) -> Result<()> {
    let Some(store) = store else {
        // No vault yet: leave layers unmarked so a later vault-backed load
        // can still migrate literal headers.
        return Ok(());
    };
    let paths = crate::config::dirs::config_file_paths_for_load(cwd);
    let seen = MIGRATED_LAYERS.get_or_init(|| Mutex::new(HashSet::new()));
    let mut seen = seen.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let pending = paths
        .into_iter()
        .filter(|path| !seen.contains(path))
        .collect::<Vec<_>>();
    if pending.is_empty() {
        return Ok(());
    }

    // Every named secret the literal→`$secret:` migration mints is claimed for
    // (provider, this canonical workspace root) through the in-transaction
    // ownership guard. Canonicalize the root the same way every other ownership
    // path does so the claim matches later owner-scoped resolution.
    let project_root = crate::secret_ownership::canonical_owner_root(&cwd.display().to_string());
    match load_paths_with_secret_migration_store(&pending, Some(store), &project_root) {
        Ok((_, Some(notice))) => eprintln!("{}", notice.render()),
        Ok((_, None)) => {}
        Err(error) => return Err(error),
    }
    for path in pending {
        seen.insert(path);
    }
    Ok(())
}

fn open_secret_store(store_path: Option<&Path>) -> Result<CredentialStore> {
    open_secret_store_impl(store_path)
}

#[cfg(not(any(test, feature = "test-support")))]
fn open_secret_store_impl(store_path: Option<&Path>) -> Result<CredentialStore> {
    let _ = store_path;
    anyhow::bail!("secret-ref path-open is test-only; production must inject a vault-backed store")
}

#[cfg(any(test, feature = "test-support"))]
include!("secret_ref_test_open.rs");

#[allow(dead_code)]
fn load_paths_with_secret_migration(
    config_paths: &[PathBuf],
    store_path: Option<&Path>,
) -> Result<(ProvidersConfig, Option<SecretRefNotice>)> {
    let mut store = open_secret_store(store_path)?;
    // Path-open is a test-only legacy-file store; its guarded write falls back to
    // an ungated file write (no ownership tables), so the root is unused.
    load_paths_with_secret_migration_store(config_paths, Some(&mut store), "")
}

fn load_paths_with_secret_migration_store(
    config_paths: &[PathBuf],
    store: Option<&mut CredentialStore>,
    project_root: &str,
) -> Result<(ProvidersConfig, Option<SecretRefNotice>)> {
    let notice = match store {
        Some(store) => migrate_provider_files_in_store(config_paths, store, project_root)?,
        None => None,
    };
    // Same barrier as every other effective resolution, and fallible here so
    // the daemon's config source reports a typed error rather than serving an
    // ambiguous snapshot behind an unmaskable pending transaction.
    let providers = ConfigDoc::try_load_effective_from_paths(config_paths)?;
    Ok((providers, notice))
}

pub fn protect_literal_headers(
    providers: &mut BTreeMap<String, ProviderEntry>,
    store_path: Option<&Path>,
) -> Result<Option<SecretRefNotice>> {
    if !has_literal_secret_candidates(providers) {
        return Ok(None);
    }
    let notice_path = match store_path {
        Some(path) => path.to_path_buf(),
        None => PathBuf::from("vault"),
    };
    // Path-open is test-only. Production callers inject a vault-backed store
    // via [`protect_literal_headers_in_store`].
    let mut store = open_secret_store(store_path)?;
    protect_literal_headers_in_store_with_notice(providers, &mut store, notice_path)
}

pub fn protect_literal_headers_in_store(
    providers: &mut BTreeMap<String, ProviderEntry>,
    store: &mut CredentialStore,
) -> Result<Option<SecretRefNotice>> {
    protect_literal_headers_in_store_with_notice(providers, store, PathBuf::from("vault"))
}

fn has_literal_secret_candidates(providers: &BTreeMap<String, ProviderEntry>) -> bool {
    providers.values().any(|entry| {
        entry
            .headers
            .iter()
            .any(|header| literal_secret_candidate(&header.value))
    })
}

fn protect_literal_headers_in_store_with_notice(
    providers: &mut BTreeMap<String, ProviderEntry>,
    store: &mut CredentialStore,
    notice_path: PathBuf,
) -> Result<Option<SecretRefNotice>> {
    let mut migrated = 0;
    for (provider_id, entry) in providers {
        let mut reserved_names = entry
            .headers
            .iter()
            .flat_map(|header| crate::envref::referenced_names(&header.value))
            .filter_map(|name| name.strip_prefix("secret:").map(str::to_string))
            .collect::<HashSet<_>>();
        for header in &mut entry.headers {
            if !literal_secret_candidate(&header.value) {
                continue;
            }
            let name = (1..)
                .map(|ordinal| {
                    if ordinal == 1 {
                        provider_id.clone()
                    } else {
                        format!("{provider_id}-{ordinal}")
                    }
                })
                .find(|candidate| !reserved_names.contains(candidate))
                .expect("unbounded generated secret-name search");
            reserved_names.insert(name.clone());
            store.set_named_secret(&name, &header.value);
            header.value = format!("$secret:{name}");
            migrated += 1;
        }
    }
    if migrated == 0 {
        return Ok(None);
    }
    store.save()?;
    Ok(Some(SecretRefNotice {
        migrated,
        store_path: notice_path,
    }))
}

#[allow(dead_code)]
fn migrate_provider_files(
    config_paths: &[PathBuf],
    store_path: Option<&Path>,
) -> Result<Option<SecretRefNotice>> {
    let mut store = open_secret_store(store_path)?;
    // Test-only path-open store: the guarded write is ungated on the legacy-file
    // backend, so the root is unused here.
    migrate_provider_files_in_store(config_paths, &mut store, "")
}

fn migrate_provider_files_in_store(
    config_paths: &[PathBuf],
    store: &mut CredentialStore,
    project_root: &str,
) -> Result<Option<SecretRefNotice>> {
    let mut changed = Vec::new();
    let mut migrated = 0;

    for config_path in config_paths {
        let Some(config_dir) = config_path.parent() else {
            continue;
        };
        let providers_dir = config_dir.join("providers");
        let Ok(entries) = std::fs::read_dir(&providers_dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(provider_id) = crate::config::providers::provider_id_from_file_name(&path)
            else {
                continue;
            };
            let mut raw = crate::config::providers::load_provider_raw_file(&path)?;
            let Some(headers) = raw.get_mut("headers").and_then(Value::as_array_mut) else {
                continue;
            };
            let mut ordinal = 0;
            let mut file_changed = false;
            for header in headers {
                let Some(value) = header
                    .as_object_mut()
                    .and_then(|header| header.get_mut("value"))
                    .and_then(|value| value.as_str())
                    .map(str::to_string)
                else {
                    continue;
                };
                if !literal_secret_candidate(&value) {
                    continue;
                }
                ordinal += 1;
                let preferred = if ordinal == 1 {
                    provider_id.clone()
                } else {
                    format!("{provider_id}-{ordinal}")
                };
                let name = migration_secret_name(&*store, &preferred, &value);
                // Route the migration write through the in-transaction ownership
                // funnel: it fails closed on a foreign/cross-kind name and claims
                // the provider name it mints for (provider, this workspace root),
                // BEFORE the referencing config is republished below. On the
                // production vault backend this is `mutate_owner_named_secret_
                // guarded` (guard + AEAD write + claim in one `BEGIN IMMEDIATE`);
                // on the test legacy-file backend it is an ungated file write.
                store.set_named_secret_owned_and_save_published(
                    &name,
                    &value,
                    crate::secret_ownership::OWNER_KIND_PROVIDER,
                    project_root,
                )?;
                if let Some(object) = header.as_object_mut() {
                    object.insert(
                        "value".to_string(),
                        Value::String(format!("$secret:{name}")),
                    );
                }
                migrated += 1;
                file_changed = true;
            }
            if file_changed {
                changed.push((path, Value::Object(raw)));
            }
        }
    }

    if migrated == 0 {
        return Ok(None);
    }

    // Each migrated secret was already durably written AND claimed (crash-atomic)
    // by `set_named_secret_owned_and_save_published` in the loop above, before any
    // config file is rewritten below. A crash may leave an unreferenced-but-owned
    // secret, but can never leave config pointing at a value that was not durably
    // stored, nor a name claimed for a config that was never published.
    for (path, raw) in changed {
        let pretty = serde_json::to_string_pretty(&raw)?;
        std::fs::write(&path, format!("{pretty}\n"))
            .with_context(|| format!("rewriting provider config {}", path.display()))?;
    }
    Ok(Some(SecretRefNotice {
        migrated,
        store_path: PathBuf::from("vault"),
    }))
}

fn migration_secret_name(store: &CredentialStore, preferred: &str, value: &str) -> String {
    if store
        .named_secret(preferred)
        .is_none_or(|existing| existing == value)
    {
        return preferred.to_string();
    }
    for suffix in 2.. {
        let candidate = format!("{preferred}-{suffix}");
        if store
            .named_secret(&candidate)
            .is_none_or(|existing| existing == value)
        {
            return candidate;
        }
    }
    unreachable!("unbounded secret-name suffix search")
}

pub fn looks_like_literal_secret(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() >= 20 {
        return true;
    }
    let compact_len = trimmed
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .count();
    compact_len >= 12
}

fn literal_secret_candidate(value: &str) -> bool {
    let resolved = crate::envref::resolve_with_sources(value, |_| None, |_| None);
    resolved.referenced.is_empty() && looks_like_literal_secret(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::providers::HeaderSpec;

    fn write_provider(config_path: &Path, provider_id: &str, value: &str) -> PathBuf {
        std::fs::create_dir_all(config_path.parent().unwrap().join("providers")).unwrap();
        std::fs::write(config_path, "{}\n").unwrap();
        let provider_path =
            crate::config::providers::provider_file_path_for_config(config_path, provider_id)
                .unwrap();
        let raw = serde_json::json!({
            "url": "https://example.test/v1",
            "headers": [{ "name": "Authorization", "value": value }],
            "unknown_preserved": true
        });
        std::fs::write(&provider_path, serde_json::to_string_pretty(&raw).unwrap()).unwrap();
        provider_path
    }

    #[test]
    fn provider_view_redacts_url_credentials_and_query() {
        let secret = "provider-url-secret";
        let providers = ProvidersConfig {
            providers: BTreeMap::from([(
                "custom".to_string(),
                ProviderEntry {
                    url: format!("https://user:{secret}@api.example.test/v1?key={secret}"),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        let view = redact_provider_view(&providers);
        let url = &view.providers["custom"].entry.url;
        assert_eq!(url, "https://api.example.test/v1");
        assert!(!url.contains(secret));
    }

    #[test]
    fn migrates_literal_header_to_secret_ref() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config/config.json");
        let store_path = tmp.path().join("state/credentials.json");
        let literal = "Bearer sk-migration-secret-123456";
        let provider_path = write_provider(&config_path, "openai", literal);

        let (loaded, notice) =
            load_paths_with_secret_migration(std::slice::from_ref(&config_path), Some(&store_path))
                .unwrap();
        let notice = notice.unwrap();
        assert_eq!(notice.migrated, 1);
        let rendered_notice = notice.render();
        // Secrets now land in the daemon-owned vault, so the migration notice
        // names "vault" rather than echoing a concrete credentials.json path.
        assert!(rendered_notice.contains("vault"));
        assert!(!rendered_notice.contains(literal));
        assert_eq!(
            loaded.providers["openai"].headers[0].value,
            "$secret:openai"
        );
        let raw = std::fs::read_to_string(provider_path).unwrap();
        assert!(raw.contains("$secret:openai"));
        assert!(!raw.contains(literal));
        assert!(raw.contains("unknown_preserved"));
        let store = CredentialStore::open(store_path).unwrap();
        assert_eq!(store.named_secret("openai"), Some(literal));
    }

    #[test]
    fn migration_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config/config.json");
        let store_path = tmp.path().join("state/credentials.json");
        let literal = "Bearer sk-migration-secret-123456";
        let provider_path = write_provider(&config_path, "openai", literal);

        assert!(
            migrate_provider_files(std::slice::from_ref(&config_path), Some(&store_path))
                .unwrap()
                .is_some()
        );
        let after_first = std::fs::read_to_string(&provider_path).unwrap();
        assert!(
            migrate_provider_files(&[config_path], Some(&store_path))
                .unwrap()
                .is_none()
        );
        assert_eq!(std::fs::read_to_string(provider_path).unwrap(), after_first);
    }

    #[test]
    fn literal_key_entry_writes_secret_ref() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join("state/credentials.json");
        let literal = "Bearer sk-editor-secret-123456";
        let mut providers = BTreeMap::from([(
            "openai".to_string(),
            ProviderEntry {
                url: "https://example.test/v1".into(),
                headers: vec![HeaderSpec {
                    name: "Authorization".into(),
                    value: literal.into(),
                }],
                ..ProviderEntry::default()
            },
        )]);

        let notice = protect_literal_headers(&mut providers, Some(&store_path))
            .unwrap()
            .unwrap();
        assert_eq!(providers["openai"].headers[0].value, "$secret:openai");
        assert_eq!(
            CredentialStore::open(store_path)
                .unwrap()
                .named_secret("openai"),
            Some(literal)
        );
        assert!(!notice.render().contains(literal));
    }

    #[test]
    fn editing_one_of_multiple_secret_headers_preserves_stable_names() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join("state/credentials.json");
        let mut store = CredentialStore::open(store_path.clone()).unwrap();
        store.set_named_secret("openai", "Bearer sk-authorization-original");
        store.set_named_secret("openai-2", "sk-secondary-original");
        store.save().unwrap();
        let mut providers = BTreeMap::from([(
            "openai".to_string(),
            ProviderEntry {
                headers: vec![
                    HeaderSpec {
                        name: "Authorization".into(),
                        value: "$secret:openai".into(),
                    },
                    HeaderSpec {
                        name: "X-API-Key".into(),
                        value: "sk-secondary-replacement-value".into(),
                    },
                ],
                ..Default::default()
            },
        )]);

        protect_literal_headers(&mut providers, Some(&store_path)).unwrap();

        assert_eq!(providers["openai"].headers[0].value, "$secret:openai");
        assert_eq!(providers["openai"].headers[1].value, "$secret:openai-2");
        let saved = CredentialStore::open(store_path).unwrap();
        assert_eq!(
            saved.named_secret("openai"),
            Some("Bearer sk-authorization-original")
        );
        assert_eq!(
            saved.named_secret("openai-2"),
            Some("sk-secondary-replacement-value")
        );
    }

    #[test]
    fn adding_literal_after_deleted_first_header_does_not_overwrite_remaining_ref() {
        let tmp = tempfile::tempdir().unwrap();
        let store_path = tmp.path().join("state/credentials.json");
        let mut store = CredentialStore::open(store_path.clone()).unwrap();
        store.set_named_secret("openai", "sk-deleted-header-value");
        store.set_named_secret("openai-2", "sk-remaining-header-value");
        store.save().unwrap();
        let mut providers = BTreeMap::from([(
            "openai".to_string(),
            ProviderEntry {
                headers: vec![
                    HeaderSpec {
                        name: "X-Existing".into(),
                        value: "$secret:openai-2".into(),
                    },
                    HeaderSpec {
                        name: "X-New".into(),
                        value: "sk-new-header-replacement-value".into(),
                    },
                ],
                ..Default::default()
            },
        )]);

        protect_literal_headers(&mut providers, Some(&store_path)).unwrap();

        assert_eq!(providers["openai"].headers[0].value, "$secret:openai-2");
        assert_eq!(providers["openai"].headers[1].value, "$secret:openai");
        let saved = CredentialStore::open(store_path).unwrap();
        assert_eq!(
            saved.named_secret("openai-2"),
            Some("sk-remaining-header-value")
        );
        assert_eq!(
            saved.named_secret("openai"),
            Some("sk-new-header-replacement-value")
        );
    }

    #[test]
    fn secret_ref_notice_names_store_path() {
        let notice = SecretRefNotice {
            migrated: 1,
            store_path: PathBuf::from("/tmp/cockpit-state/credentials.json"),
        };
        let rendered = notice.render();
        assert!(rendered.contains("/tmp/cockpit-state/credentials.json"));
        assert!(rendered.contains("$secret:"));
    }

    #[test]
    fn provider_headers_use_injected_vault() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let mut providers = BTreeMap::from([(
            "openai".to_string(),
            ProviderEntry {
                url: "https://api.openai.com/v1".into(),
                headers: vec![crate::config::providers::HeaderSpec {
                    name: "Authorization".into(),
                    value: "sk-provider-header-secret-123456".into(),
                }],
                ..Default::default()
            },
        )]);
        let notice = protect_literal_headers(&mut providers, None)
            .unwrap()
            .unwrap();
        assert_eq!(providers["openai"].headers[0].value, "$secret:openai");
        assert!(
            !crate::credentials::default_path().unwrap().exists(),
            "provider headers must persist through the vault"
        );
        let store = crate::credentials::CredentialStore::open_default().unwrap();
        assert_eq!(
            store.named_secret("openai"),
            Some("sk-provider-header-secret-123456")
        );
        assert!(notice.migrated >= 1);
    }

    #[test]
    fn ask_and_setup_use_injected_vault_not_credentials_json() {
        let credentials_src = include_str!("credentials.rs");
        assert!(credentials_src.contains("from_vault"));
        let setup_src = include_str!("../../../apps/cli/src/commands/setup.rs");
        assert!(
            setup_src.contains("ApplyProviderMutation"),
            "setup must persist provider headers through the daemon ApplyProviderMutation owner RPC rather than opening a local store"
        );
        assert!(
            !setup_src.contains("CredentialStore::open(state_home.join"),
            "setup tests/production must not treat credentials.json as the live store"
        );
        let secret_ref_src = include_str!("secret_ref.rs");
        assert!(
            secret_ref_src.contains("protect_literal_headers_in_store"),
            "provider-header protection must accept an injected store"
        );
        assert!(
            secret_ref_src.contains(
                "secret-ref path-open is test-only; production must inject a vault-backed store"
            ),
            "production path-open must fail closed"
        );
    }

    // AC10: the daemon command-secret executor/cache is generic — a preset that
    // maps a product toggle (e.g. "use the platform CLI token") to a concrete
    // argv lives in the UI layer, never in the resolution module.
    #[test]
    fn secret_command_module_has_no_provider_preset_strings() {
        let src = include_str!("secret_command.rs").to_ascii_lowercase();
        assert!(
            !src.contains("copilot"),
            "secret_command.rs must not name a provider preset"
        );
        for token in src.split(|c: char| !c.is_ascii_alphanumeric()) {
            assert_ne!(
                token, "gh",
                "secret_command.rs must not name the gh CLI; presets live in the UI"
            );
        }
    }

    #[test]
    fn protect_literal_headers_without_candidates_does_not_open_store() {
        let mut providers = BTreeMap::from([(
            "openai".to_string(),
            ProviderEntry {
                url: "https://api.openai.com/v1".into(),
                headers: vec![HeaderSpec {
                    name: "Authorization".into(),
                    value: "$secret:openai".into(),
                }],
                ..Default::default()
            },
        )]);
        let notice = protect_literal_headers(&mut providers, None).unwrap();
        assert!(notice.is_none());
        assert_eq!(providers["openai"].headers[0].value, "$secret:openai");
    }

    #[test]
    fn protect_literal_headers_in_store_uses_injected_vault() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let db = crate::db::Db::open_in_memory().unwrap();
        let vault = crate::secure_key::open_for_db(&db).unwrap();
        let mut store = CredentialStore::from_vault(vault).unwrap();
        let literal = "sk-injected-store-secret-123456";
        let mut providers = BTreeMap::from([(
            "openai".to_string(),
            ProviderEntry {
                url: "https://api.openai.com/v1".into(),
                headers: vec![HeaderSpec {
                    name: "Authorization".into(),
                    value: literal.into(),
                }],
                ..Default::default()
            },
        )]);
        let notice = protect_literal_headers_in_store(&mut providers, &mut store)
            .unwrap()
            .unwrap();
        assert_eq!(providers["openai"].headers[0].value, "$secret:openai");
        assert_eq!(store.named_secret("openai"), Some(literal));
        assert_eq!(notice.migrated, 1);
        assert!(!crate::credentials::default_path().unwrap().exists());
    }

    #[test]
    fn no_store_prepare_does_not_mark_layers_migrated() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let config_path = tmp.path().join(".cockpit/config.json");
        let literal = "Bearer sk-unmarked-layer-secret-123456";
        let provider_path = write_provider(&config_path, "openai", literal);
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::with_workspace_trust_policy(policy.clone(), || {
            prepare_effective_layers(tmp.path());
        });
        let raw = std::fs::read_to_string(&provider_path).unwrap();
        assert!(
            raw.contains(literal),
            "no-store prepare must not rewrite: {raw}"
        );

        let db = crate::db::Db::open_in_memory().unwrap();
        let vault = crate::secure_key::open_for_db(&db).unwrap();
        let store = CredentialStore::from_vault(vault).unwrap();
        crate::config::trust::with_workspace_trust_policy(policy, || {
            prepare_effective_layers_with_store(tmp.path(), Some(store))
                .expect("vault-backed prepare");
        });
        let raw = std::fs::read_to_string(&provider_path).unwrap();
        assert!(raw.contains("$secret:openai"), "{raw}");
        assert!(!raw.contains(literal), "{raw}");
    }

    fn named_ownership_exists(
        db: &crate::db::Db,
        item_id: &str,
        owner_kind: &str,
        project_root: &str,
    ) -> bool {
        let item_id = item_id.to_string();
        let owner_kind = owner_kind.to_string();
        let project_root = project_root.to_string();
        db.blocking_read_for_sync_ui(move |conn| {
            Ok(conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM secret_named_ownership
                 WHERE item_id = ?1 AND owner_kind = ?2 AND project_root = ?3)",
                rusqlite::params![item_id, owner_kind, project_root],
                |row| row.get::<_, bool>(0),
            )?)
        })
        .unwrap()
    }

    // Gap 3: the literal→`$secret:` migration claims the provider name it mints,
    // for (provider, canonical workspace root), through the ownership funnel.
    #[test]
    fn migration_claims_generated_provider_name() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let config_path = tmp.path().join(".cockpit/config.json");
        let literal = "Bearer sk-migration-owned-secret-123456";
        let provider_path = write_provider(&config_path, "openai", literal);
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        let db = crate::db::Db::open_in_memory().unwrap();
        let vault = crate::secure_key::open_for_db(&db).unwrap();
        let store = CredentialStore::from_vault(vault).unwrap();
        crate::config::trust::with_workspace_trust_policy(policy, || {
            prepare_effective_layers_with_store(tmp.path(), Some(store)).expect("vault prepare");
        });

        let raw = std::fs::read_to_string(&provider_path).unwrap();
        assert!(raw.contains("$secret:openai"), "{raw}");
        let canonical =
            crate::secret_ownership::canonical_owner_root(&tmp.path().display().to_string());
        assert!(
            named_ownership_exists(&db, "openai", "provider", &canonical),
            "migration must claim the name it mints for this workspace"
        );
    }

    // Gap 3: the migration write is guarded — a name already owned by a foreign
    // (kind, root) fails the migration CLOSED, and the referencing config is NOT
    // republished (no `$secret:` pointing at a foreign-owned value).
    #[test]
    fn migration_fails_closed_on_foreign_owned_name() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let config_path = tmp.path().join(".cockpit/config.json");
        let literal = "Bearer sk-foreign-owned-secret-123456";
        let provider_path = write_provider(&config_path, "openai", literal);
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        let db = crate::db::Db::open_in_memory().unwrap();
        let vault = crate::secure_key::open_for_db(&db).unwrap();
        // A DIFFERENT workspace already owns the name the migration would mint.
        db.blocking_write_for_sync_maintenance(|conn| {
            conn.execute(
                "INSERT INTO secret_named_ownership (item_id, owner_kind, project_root, created_at)
                 VALUES ('openai', 'provider', '/foreign/ws', 0)",
                [],
            )?;
            Ok(())
        })
        .unwrap();
        let store = CredentialStore::from_vault(vault).unwrap();

        let result = crate::config::trust::with_workspace_trust_policy(policy, || {
            prepare_effective_layers_with_store(tmp.path(), Some(store))
        });
        assert!(
            result.is_err(),
            "a foreign-owned generated name must fail the migration closed"
        );
        let raw = std::fs::read_to_string(&provider_path).unwrap();
        assert!(
            raw.contains(literal),
            "the config must NOT be rewritten to reference a foreign-owned name: {raw}"
        );
        assert!(!raw.contains("$secret:openai"), "{raw}");
    }
}
