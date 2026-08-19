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
                let credential_configured =
                    entry.credential_ref.is_some() || !entry.headers.is_empty();
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
        extended_config_json: None,
    }
}

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

    match load_paths_with_secret_migration_store(&pending, Some(store)) {
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

fn load_paths_with_secret_migration(
    config_paths: &[PathBuf],
    store_path: Option<&Path>,
) -> Result<(ProvidersConfig, Option<SecretRefNotice>)> {
    let mut store = open_secret_store(store_path)?;
    load_paths_with_secret_migration_store(config_paths, Some(&mut store))
}

fn load_paths_with_secret_migration_store(
    config_paths: &[PathBuf],
    store: Option<&mut CredentialStore>,
) -> Result<(ProvidersConfig, Option<SecretRefNotice>)> {
    let notice = match store {
        Some(store) => migrate_provider_files_in_store(config_paths, store)?,
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

fn migrate_provider_files(
    config_paths: &[PathBuf],
    store_path: Option<&Path>,
) -> Result<Option<SecretRefNotice>> {
    let mut store = open_secret_store(store_path)?;
    migrate_provider_files_in_store(config_paths, &mut store)
}

fn migrate_provider_files_in_store(
    config_paths: &[PathBuf],
    store: &mut CredentialStore,
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
                let name = migration_secret_name(&store, &preferred, &value);
                store.set_named_secret(&name, &value);
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

    // Commit secrets first: a crash may leave an unreferenced secret, but can
    // never leave config pointing at a value that was not durably stored.
    store.save()?;
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
            setup_src.contains("SaveProviderConfig"),
            "setup must persist provider headers through the daemon SaveProviderConfig owner RPC rather than opening a local store"
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
}
