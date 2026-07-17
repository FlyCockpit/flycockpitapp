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
pub(crate) struct SecretRefNotice {
    pub(crate) migrated: usize,
    pub(crate) store_path: PathBuf,
}

impl SecretRefNotice {
    pub(crate) fn render(&self) -> String {
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
pub(crate) fn load_effective(cwd: &Path) -> ProvidersConfig {
    if let Err(error) = migrate_effective_layers_once(cwd) {
        tracing::warn!(%error, "provider secret migration could not complete");
    }
    ConfigDoc::load_effective(cwd)
}

fn migrate_effective_layers_once(cwd: &Path) -> Result<()> {
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

    let store_path = crate::credentials::default_path()
        .context("could not locate credentials path for provider secret migration")?;
    match load_paths_with_secret_migration(&pending, &store_path) {
        Ok((_, Some(notice))) => eprintln!("{}", notice.render()),
        Ok((_, None)) => {}
        Err(error) => return Err(error),
    }
    for path in pending {
        seen.insert(path);
    }
    Ok(())
}

fn load_paths_with_secret_migration(
    config_paths: &[PathBuf],
    store_path: &Path,
) -> Result<(ProvidersConfig, Option<SecretRefNotice>)> {
    let notice = migrate_provider_files(config_paths, store_path)?;
    let providers = ConfigDoc::providers_from_paths(config_paths);
    Ok((providers, notice))
}

pub(crate) fn protect_literal_headers(
    providers: &mut BTreeMap<String, ProviderEntry>,
    store_path: Option<&Path>,
) -> Result<Option<SecretRefNotice>> {
    let store_path = match store_path {
        Some(path) => path.to_path_buf(),
        None => crate::credentials::default_path()
            .context("could not locate credentials path for provider secrets")?,
    };
    let mut store = CredentialStore::open(store_path.clone())?;
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
        store_path,
    }))
}

fn migrate_provider_files(
    config_paths: &[PathBuf],
    store_path: &Path,
) -> Result<Option<SecretRefNotice>> {
    let mut store = CredentialStore::open(store_path.to_path_buf())?;
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
        store_path: store_path.to_path_buf(),
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

pub(crate) fn looks_like_literal_secret(value: &str) -> bool {
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
    fn migrates_literal_header_to_secret_ref() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config/config.json");
        let store_path = tmp.path().join("state/credentials.json");
        let literal = "Bearer sk-migration-secret-123456";
        let provider_path = write_provider(&config_path, "openai", literal);

        let (loaded, notice) =
            load_paths_with_secret_migration(std::slice::from_ref(&config_path), &store_path)
                .unwrap();
        let notice = notice.unwrap();
        assert_eq!(notice.migrated, 1);
        let rendered_notice = notice.render();
        assert!(rendered_notice.contains(&store_path.display().to_string()));
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
            migrate_provider_files(std::slice::from_ref(&config_path), &store_path)
                .unwrap()
                .is_some()
        );
        let after_first = std::fs::read_to_string(&provider_path).unwrap();
        assert!(
            migrate_provider_files(&[config_path], &store_path)
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
        assert!(!rendered.contains("sk-secret"));
    }
}
