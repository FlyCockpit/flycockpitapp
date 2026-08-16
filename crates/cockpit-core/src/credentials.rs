//! Credential facade over the wrap-key vault.
//!
//! Production construction is [`CredentialStore::from_vault`]. Provider records,
//! named secrets, and subscription-ack flags live as AEAD items
//! (`credential_record`, `named_secret`, `subscription_ack`). A leftover
//! `credentials.json` may still exist on disk. After the vault is the
//! authority, `save` / `set` write vault rows only and must not recreate the
//! JSON path.
//!
//! Path-open remains for `#[cfg(test)]` fixtures that have not yet moved.
//! Production login, refresh, logout, MCP, provider-header, `ask`, and setup
//! paths use the injected vault handle.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use cockpit_db::secret_vault::SecretVaultKind;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::secure_key::SecretVault;

const SUBSCRIPTION_ACK_PREFIX: &str = "subscription-oauth-ack:";

/// Default credentials path: `~/.local/state/cockpit/credentials.json`.
/// Honors `XDG_STATE_HOME` per the XDG spec.
pub fn default_path() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_STATE_HOME")
        && !xdg.trim().is_empty()
    {
        return Some(PathBuf::from(xdg).join("cockpit/credentials.json"));
    }
    let home = dirs::home_dir()?;
    Some(home.join(".local/state/cockpit/credentials.json"))
}

enum CredentialBackend {
    Vault(Arc<SecretVault>),
    LegacyFile { path: PathBuf },
}

pub struct CredentialStore {
    backend: CredentialBackend,
    records: BTreeMap<String, Value>,
    secrets: BTreeMap<String, String>,
    record_mutations: Vec<RecordMutation>,
    secret_mutations: Vec<SecretMutation>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct CredentialFile {
    #[serde(
        default,
        rename = "$secrets",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    secrets: BTreeMap<String, String>,
    #[serde(flatten)]
    records: BTreeMap<String, Value>,
}

#[derive(Debug, Clone)]
enum RecordMutation {
    Set(String, Value),
    Remove(String),
}

#[derive(Debug, Clone)]
enum SecretMutation {
    Set(String, String),
    Remove(String),
}

impl CredentialStore {
    /// Production constructor: vault-backed facade.
    pub fn from_vault(vault: Arc<SecretVault>) -> Result<Self> {
        let (records, secrets) = load_from_vault(&vault)?;
        Ok(Self {
            backend: CredentialBackend::Vault(vault),
            records,
            secrets,
            record_mutations: Vec::new(),
            secret_mutations: Vec::new(),
        })
    }

    /// Import-only / test fixtures. Production login, refresh, logout, MCP,
    /// provider-header, `ask`, and setup paths must use [`Self::from_vault`]
    /// or [`Self::open_default`].
    #[cfg(any(test, feature = "test-support"))]
    pub fn open(path: PathBuf) -> Result<Self> {
        Self::open_legacy_file(path)
    }

    /// Read a leftover `credentials.json` for the import saga.
    pub(crate) fn open_legacy_file(path: PathBuf) -> Result<Self> {
        ensure_parent_dir_private(&path)?;
        let data = read_credential_file(&path)?;
        Ok(Self {
            backend: CredentialBackend::LegacyFile { path },
            records: data.records,
            secrets: data.secrets,
            record_mutations: Vec::new(),
            secret_mutations: Vec::new(),
        })
    }

    pub fn open_default() -> Result<Self> {
        let db =
            crate::db::Db::open_default().context("opening cockpit DB for credential vault")?;
        let vault = crate::secure_key::vault_for_db(&db)
            .map_err(|e| anyhow::anyhow!("opening secret vault for credentials: {e}"))?;
        Self::from_vault(vault)
    }

    /// Settings/test fixtures pass an explicit leftover JSON path. Production
    /// construction with `None` stays on the process vault.
    pub fn open_for_path_or_default(path: Option<&Path>) -> Result<Self> {
        #[cfg(any(test, feature = "test-support"))]
        if let Some(path) = path {
            return Self::open(path.to_path_buf());
        }
        let _ = path;
        Self::open_default()
    }

    /// Open the credential store without creating parent directories, lock
    /// files, or repairing permissions. Test / diagnostic fixtures only.
    #[cfg(any(test, feature = "test-support"))]
    pub fn open_readonly(path: PathBuf) -> Result<Self> {
        let data = read_credential_file_readonly(&path)?;
        Ok(Self {
            backend: CredentialBackend::LegacyFile { path },
            records: data.records,
            secrets: data.secrets,
            record_mutations: Vec::new(),
            secret_mutations: Vec::new(),
        })
    }

    pub fn open_default_readonly() -> Result<Self> {
        Self::open_default()
    }

    pub fn get(&self, provider_id: &str) -> Option<&Value> {
        self.records.get(provider_id)
    }

    /// Convenience for the common API-key case.
    pub fn api_key(&self, provider_id: &str) -> Option<String> {
        self.records
            .get(provider_id)?
            .get("api_key")?
            .as_str()
            .map(str::to_string)
    }

    pub fn set(&mut self, provider_id: impl Into<String>, value: Value) {
        let provider_id = provider_id.into();
        self.records.insert(provider_id.clone(), value.clone());
        self.record_mutations
            .push(RecordMutation::Set(provider_id, value));
    }

    pub fn set_api_key(&mut self, provider_id: impl Into<String>, key: impl Into<String>) {
        self.set(provider_id, serde_json::json!({ "api_key": key.into() }));
    }

    pub fn remove(&mut self, provider_id: &str) {
        self.records.remove(provider_id);
        self.record_mutations
            .push(RecordMutation::Remove(provider_id.to_string()));
    }

    pub fn named_secret(&self, name: &str) -> Option<&str> {
        self.secrets.get(name).map(String::as_str)
    }

    pub fn set_named_secret(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        let value = value.into();
        self.secrets.insert(name.clone(), value.clone());
        self.secret_mutations.push(SecretMutation::Set(name, value));
    }

    pub fn remove_named_secret(&mut self, name: &str) {
        self.secrets.remove(name);
        self.secret_mutations
            .push(SecretMutation::Remove(name.to_string()));
    }

    /// Named-secret keys.
    ///
    /// Deliberately **not** `pub`. Enumerating this namespace is an inventory
    /// oracle, and sealed values must never be inventoriable through a generic
    /// credential surface. Persistent sealed literals live in their own
    /// compartment — a separate file with a separate API that has no listing
    /// surface at all — so this method cannot reach them either way. It stays
    /// crate-private so no public, re-exported, status, debug, doctor, or
    /// export path can grow onto it.
    #[cfg(test)]
    pub(crate) fn list_named_secrets(&self) -> Vec<String> {
        self.secrets.keys().cloned().collect()
    }

    pub(crate) fn named_secret_entries(&self) -> impl Iterator<Item = (&str, &str)> {
        self.secrets
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }

    pub(crate) fn provider_credential_entries(&self) -> impl Iterator<Item = (String, String)> {
        let mut entries = Vec::new();
        for (provider, record) in &self.records {
            collect_credential_values(
                record,
                &format!("$credentials:{provider}"),
                true,
                &mut entries,
            );
        }
        entries.into_iter()
    }

    pub fn save(&mut self) -> Result<()> {
        match &self.backend {
            CredentialBackend::Vault(vault) => {
                save_mutations_to_vault(vault, &self.record_mutations, &self.secret_mutations)?;
                let (records, secrets) = load_from_vault(vault)?;
                self.records = records;
                self.secrets = secrets;
                self.record_mutations.clear();
                self.secret_mutations.clear();
                Ok(())
            }
            CredentialBackend::LegacyFile { path } => {
                // File writes are import-saga / test fixtures only. After
                // vault activate, production construction is `from_vault` and
                // never reaches this arm.
                ensure_parent_dir_private(path)?;
                let _lock = lock_credential_file(path)?;
                let mut latest = read_credential_file(path)?;
                for mutation in &self.record_mutations {
                    match mutation {
                        RecordMutation::Set(id, value) => {
                            latest.records.insert(id.clone(), value.clone());
                        }
                        RecordMutation::Remove(id) => {
                            latest.records.remove(id);
                        }
                    }
                }
                for mutation in &self.secret_mutations {
                    match mutation {
                        SecretMutation::Set(name, value) => {
                            latest.secrets.insert(name.clone(), value.clone());
                        }
                        SecretMutation::Remove(name) => {
                            latest.secrets.remove(name);
                        }
                    }
                }
                write_credential_file_atomic(path, &latest)?;
                self.records = latest.records;
                self.secrets = latest.secrets;
                self.record_mutations.clear();
                self.secret_mutations.clear();
                Ok(())
            }
        }
    }

    pub fn save_record_merged(&self, provider_id: &str, value: Value) -> Result<()> {
        match &self.backend {
            CredentialBackend::Vault(vault) => {
                let mut latest = Self::from_vault(vault.clone())?;
                latest.set(provider_id, value);
                latest.save()
            }
            CredentialBackend::LegacyFile { path } => {
                let mut latest = Self::open_legacy_file(path.clone())?;
                latest.set(provider_id, value);
                latest.save()
            }
        }
    }

    pub fn remove_record_merged(&self, provider_id: &str) -> Result<()> {
        match &self.backend {
            CredentialBackend::Vault(vault) => {
                let mut latest = Self::from_vault(vault.clone())?;
                latest.remove(provider_id);
                latest.save()
            }
            CredentialBackend::LegacyFile { path } => {
                let mut latest = Self::open_legacy_file(path.clone())?;
                latest.remove(provider_id);
                latest.save()
            }
        }
    }

    pub fn path(&self) -> &Path {
        match &self.backend {
            CredentialBackend::LegacyFile { path } => path,
            CredentialBackend::Vault(_) => {
                static FALLBACK: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
                FALLBACK.get_or_init(|| {
                    default_path().unwrap_or_else(|| PathBuf::from("credentials.json"))
                })
            }
        }
    }

    /// Reload this store from its backing vault or leftover import file.
    pub(crate) fn reopen(&self) -> Result<Self> {
        match &self.backend {
            CredentialBackend::Vault(vault) => Self::from_vault(vault.clone()),
            CredentialBackend::LegacyFile { path } => Self::open_legacy_file(path.clone()),
        }
    }
}

fn record_kind(id: &str) -> SecretVaultKind {
    if id.starts_with(SUBSCRIPTION_ACK_PREFIX) {
        SecretVaultKind::SubscriptionAck
    } else {
        SecretVaultKind::CredentialRecord
    }
}

fn load_from_vault(
    vault: &SecretVault,
) -> Result<(BTreeMap<String, Value>, BTreeMap<String, String>)> {
    let mut records = BTreeMap::new();
    for kind in [
        SecretVaultKind::CredentialRecord,
        SecretVaultKind::SubscriptionAck,
    ] {
        for id in vault
            .list_item_ids(kind)
            .map_err(|e| anyhow::anyhow!("listing credential vault items: {e}"))?
        {
            let secret = vault
                .get_item(kind, &id)
                .map_err(|e| anyhow::anyhow!("reading credential vault item: {e}"))?;
            let value: Value = serde_json::from_slice(secret.as_slice())
                .with_context(|| format!("parsing vault credential {id}"))?;
            records.insert(id, value);
        }
    }
    let mut secrets = BTreeMap::new();
    for id in vault
        .list_item_ids(SecretVaultKind::NamedSecret)
        .map_err(|e| anyhow::anyhow!("listing named-secret vault items: {e}"))?
    {
        let secret = vault
            .get_item(SecretVaultKind::NamedSecret, &id)
            .map_err(|e| anyhow::anyhow!("reading named-secret vault item: {e}"))?;
        let value = String::from_utf8(secret.as_slice().to_vec())
            .with_context(|| format!("named secret {id} is not UTF-8"))?;
        secrets.insert(id, value);
    }
    Ok((records, secrets))
}

fn save_mutations_to_vault(
    vault: &SecretVault,
    record_mutations: &[RecordMutation],
    secret_mutations: &[SecretMutation],
) -> Result<()> {
    for mutation in record_mutations {
        match mutation {
            RecordMutation::Set(id, value) => {
                let bytes = serde_json::to_vec(value)
                    .with_context(|| format!("serializing credential {id}"))?;
                vault
                    .put_item(record_kind(id), id, &bytes)
                    .map_err(|e| anyhow::anyhow!("writing credential vault item: {e}"))?;
            }
            RecordMutation::Remove(id) => {
                vault
                    .delete_item(record_kind(id), id)
                    .map_err(|e| anyhow::anyhow!("deleting credential vault item: {e}"))?;
            }
        }
    }
    for mutation in secret_mutations {
        match mutation {
            SecretMutation::Set(name, value) => {
                vault
                    .put_item(SecretVaultKind::NamedSecret, name, value.as_bytes())
                    .map_err(|e| anyhow::anyhow!("writing named-secret vault item: {e}"))?;
            }
            SecretMutation::Remove(name) => {
                vault
                    .delete_item(SecretVaultKind::NamedSecret, name)
                    .map_err(|e| anyhow::anyhow!("deleting named-secret vault item: {e}"))?;
            }
        }
    }
    Ok(())
}

/// Collect strings whose JSON key is secret-shaped from a provider record.
/// A top-level string is also a credential because the MCP credential resolver
/// deliberately accepts that compact record form. Non-secret metadata such as
/// account IDs and expiry timestamps stays out of the redaction table.
fn collect_credential_values(
    value: &Value,
    origin: &str,
    is_record_root: bool,
    out: &mut Vec<(String, String)>,
) {
    match value {
        Value::String(value) if is_record_root => out.push((origin.to_string(), value.clone())),
        Value::Object(fields) => {
            for (key, value) in fields {
                let field_origin = format!("{origin}.{key}");
                if crate::redact::is_secret_shaped_key(key) {
                    collect_all_strings(value, &field_origin, out);
                } else {
                    collect_credential_values(value, &field_origin, false, out);
                }
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                collect_credential_values(value, &format!("{origin}[{index}]"), false, out);
            }
        }
        _ => {}
    }
}

/// A secret-shaped field can validly carry a string list (for example an
/// OAuth token set); every string below that field must be registered.
fn collect_all_strings(value: &Value, origin: &str, out: &mut Vec<(String, String)>) {
    match value {
        Value::String(value) => out.push((origin.to_string(), value.clone())),
        Value::Object(fields) => {
            for (key, value) in fields {
                collect_all_strings(value, &format!("{origin}.{key}"), out);
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                collect_all_strings(value, &format!("{origin}[{index}]"), out);
            }
        }
        _ => {}
    }
}

fn read_credential_file(path: &Path) -> Result<CredentialFile> {
    if !path.exists() {
        return Ok(CredentialFile::default());
    }
    repair_existing_file_permissions(path)?;
    read_credential_file_readonly(path)
}

fn read_credential_file_readonly(path: &Path) -> Result<CredentialFile> {
    // Fail-closed held-fd read: a symlinked, foreign-owned, hard-linked, or
    // mode-wide credential file is a typed refusal (via `PrivateFsError`), never
    // a silent read of an unprovable secret. A genuinely absent file is an empty
    // store, not a compromise.
    let Some(bytes) = crate::private_fs::read_private_file(path, "credential")? else {
        return Ok(CredentialFile::default());
    };
    let raw = String::from_utf8(bytes)
        .with_context(|| format!("credential file {} is not valid UTF-8", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(CredentialFile::default());
    }
    serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

fn lock_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    path.with_file_name(name)
}

fn lock_credential_file(path: &Path) -> Result<std::fs::File> {
    let lock_path = lock_path(path);
    ensure_parent_dir_private(&lock_path)?;
    let file = open_private_lock_file(&lock_path)?;
    file.lock()
        .with_context(|| format!("locking credential store {}", path.display()))?;
    Ok(file)
}

#[cfg(unix)]
fn open_private_lock_file(path: &Path) -> Result<std::fs::File> {
    // Route through the no-follow funnel: the lock file is opened via `openat`
    // (O_NOFOLLOW, no O_TRUNC) anchored to the held, verified 0700 parent fd,
    // then fchmod'ed 0600 and re-verified through that fd — not a path-following
    // open + path chmod that a planted symlink could redirect.
    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!("credential lock {} has no parent directory", path.display())
    })?;
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("credential lock {} has no file name", path.display()))?;
    let file = crate::private_fs::open_private_file_at(
        parent,
        name,
        crate::private_fs::PrivateFileAccess::ReadWrite,
        "credential lock",
    )
    .with_context(|| format!("opening credential lock {}", path.display()))?;
    Ok(file)
}

#[cfg(not(unix))]
fn open_private_lock_file(path: &Path) -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("opening credential lock {}", path.display()))
}

fn write_credential_file_atomic(path: &Path, data: &CredentialFile) -> Result<()> {
    let mut pretty = serde_json::to_string_pretty(data)?;
    pretty.push('\n');
    // Route credential saves through the hardened private-write funnel: a
    // crash-atomic temp created in the destination directory, moded 0600 before
    // any bytes are written, fsynced, renamed over the target, with the held
    // destination-directory fd fsynced after the rename. This replaces a bespoke
    // temp/persist that skipped the directory durability barrier.
    crate::private_fs::write_private_file(path, pretty.as_bytes())?;
    // Post-write fail-closed verification: the persisted credential file must be
    // provably private (self-owned, single-linked, exactly 0600, not a symlink),
    // or this returns a typed refusal rather than leaving a suspect secret.
    repair_existing_file_permissions(path)?;
    Ok(())
}

fn ensure_parent_dir_private(path: &Path) -> Result<()> {
    Ok(crate::private_fs::ensure_parent_dir_private(path)?)
}

fn repair_existing_file_permissions(path: &Path) -> Result<()> {
    // Fail closed: a credential file that cannot be proven private (symlink,
    // foreign owner, hard link, or an unrepairable mode) is a typed refusal,
    // not a warning the caller ignores. On non-Unix this is a documented no-op.
    Ok(crate::private_fs::repair_private_file(path, "credential")?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn provider_credential_entries_collect_nested_and_compact_credentials() {
        let tmp = TempDir::new().unwrap();
        let mut store = CredentialStore::open(tmp.path().join("credentials.json")).unwrap();
        store.set(
            "provider",
            serde_json::json!({
                "client_secret": "nested-client-secret-123456",
                "oauth": { "instanceToken": "nested-instance-token-123456" },
                "email": "not-a-credential.test"
            }),
        );
        store.set(
            "mcp:header",
            serde_json::json!("compact-header-secret-123456"),
        );

        let entries: Vec<_> = store.provider_credential_entries().collect();
        assert!(
            entries
                .iter()
                .any(|(_, value)| value == "nested-client-secret-123456")
        );
        assert!(
            entries
                .iter()
                .any(|(_, value)| value == "nested-instance-token-123456")
        );
        assert!(
            entries
                .iter()
                .any(|(_, value)| value == "compact-header-secret-123456")
        );
        assert!(
            !entries
                .iter()
                .any(|(_, value)| value == "not-a-credential.test")
        );
    }

    #[test]
    fn round_trips_an_api_key() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("credentials.json");
        let mut store = CredentialStore::open(path.clone()).unwrap();
        store.set_api_key("opencode-zen", "secret");
        store.save().unwrap();

        let store2 = CredentialStore::open(path).unwrap();
        assert_eq!(store2.api_key("opencode-zen").as_deref(), Some("secret"));
    }

    #[test]
    fn named_secrets_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("credentials.json");
        let mut store = CredentialStore::open(path.clone()).unwrap();
        store.set_named_secret("openai", "sk-first");
        store.set_named_secret("anthropic.prod", "sk-second");
        store.save().unwrap();

        let mut reopened = CredentialStore::open(path.clone()).unwrap();
        assert_eq!(reopened.named_secret("openai"), Some("sk-first"));
        assert_eq!(
            reopened.list_named_secrets(),
            vec!["anthropic.prod".to_string(), "openai".to_string()]
        );
        reopened.remove_named_secret("openai");
        reopened.save().unwrap();

        let saved = CredentialStore::open(path).unwrap();
        assert_eq!(saved.named_secret("openai"), None);
        assert_eq!(saved.named_secret("anthropic.prod"), Some("sk-second"));
    }

    #[test]
    fn named_secret_overwrite_replaces() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("credentials.json");
        let mut store = CredentialStore::open(path.clone()).unwrap();
        store.set_named_secret("openai", "old-value");
        store.save().unwrap();
        store.set_named_secret("openai", "new-value");
        store.save().unwrap();

        let saved = CredentialStore::open(path).unwrap();
        assert_eq!(saved.named_secret("openai"), Some("new-value"));
        assert_eq!(saved.list_named_secrets(), vec!["openai".to_string()]);
    }

    #[test]
    fn credential_store_concurrent_writes_preserve_records() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("credentials.json");
        let first = CredentialStore::open(path.clone()).unwrap();
        let second = CredentialStore::open(path.clone()).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

        let first_barrier = barrier.clone();
        let first_thread = std::thread::spawn(move || {
            let mut first = first;
            first.set_api_key("oauth-one", "first-value");
            first_barrier.wait();
            first.save().unwrap();
        });
        let second_thread = std::thread::spawn(move || {
            let mut second = second;
            second.set_named_secret("provider-two", "second-value");
            barrier.wait();
            second.save().unwrap();
        });
        first_thread.join().unwrap();
        second_thread.join().unwrap();

        let saved = CredentialStore::open(path).unwrap();
        assert_eq!(saved.api_key("oauth-one").as_deref(), Some("first-value"));
        assert_eq!(saved.named_secret("provider-two"), Some("second-value"));
    }

    #[test]
    fn remove_drops_record() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("credentials.json");
        let mut store = CredentialStore::open(path).unwrap();
        store.set_api_key("x", "k");
        store.remove("x");
        assert!(store.get("x").is_none());
    }

    #[test]
    fn save_record_merged_preserves_unrelated_disk_records() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("credentials.json");
        let mut first = CredentialStore::open(path.clone()).unwrap();
        first.set_api_key("stale", "old");

        let mut concurrent = CredentialStore::open(path.clone()).unwrap();
        concurrent.set_api_key("other", "keep");
        concurrent.save().unwrap();

        first
            .save_record_merged("stale", serde_json::json!({ "api_key": "new" }))
            .unwrap();

        let saved = CredentialStore::open(path).unwrap();
        assert_eq!(saved.api_key("stale").as_deref(), Some("new"));
        assert_eq!(saved.api_key("other").as_deref(), Some("keep"));
    }

    #[test]
    fn remove_record_merged_preserves_unrelated_disk_records() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("credentials.json");
        let mut first = CredentialStore::open(path.clone()).unwrap();
        first.set_api_key("stale", "old");

        let mut concurrent = CredentialStore::open(path.clone()).unwrap();
        concurrent.set_api_key("stale", "old");
        concurrent.set_api_key("other", "keep");
        concurrent.save().unwrap();

        first.remove_record_merged("stale").unwrap();

        let saved = CredentialStore::open(path).unwrap();
        assert!(saved.get("stale").is_none());
        assert_eq!(saved.api_key("other").as_deref(), Some("keep"));
    }

    #[cfg(unix)]
    #[test]
    fn file_has_0600_perms_after_save() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("credentials.json");
        let mut store = CredentialStore::open(path.clone()).unwrap();
        store.set_api_key("p", "k");
        store.save().unwrap();
        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn open_repairs_existing_broad_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("credentials.json");
        std::fs::write(&path, r#"{"p":{"api_key":"secret"}}"#).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let store = CredentialStore::open(path.clone()).unwrap();
        assert_eq!(store.api_key("p").as_deref(), Some("secret"));
        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn open_repairs_existing_broad_parent_directory_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("state/cockpit");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = dir.join("credentials.json");

        let _store = CredentialStore::open(path).unwrap();
        let perms = std::fs::metadata(&dir).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn save_creates_parent_directory_private() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("state/cockpit");
        let path = dir.join("credentials.json");
        let mut store = CredentialStore::open(path).unwrap();
        store.set_api_key("p", "k");
        store.save().unwrap();
        let perms = std::fs::metadata(&dir).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o700);
    }

    #[test]
    fn xdg_state_home_overrides_default_path() {
        // Sanity check: setting XDG_STATE_HOME points the default at it.
        let tmp = TempDir::new().unwrap();
        let env = crate::test_env::lock();
        env.set_var("XDG_STATE_HOME", tmp.path());
        let path = default_path().unwrap();
        assert!(path.starts_with(tmp.path()));
    }

    #[test]
    fn production_credentials_and_flycockpit_do_not_recreate_json_after_activate() {
        let credentials_src = include_str!("credentials.rs");
        assert!(
            credentials_src.contains("from_vault"),
            "production constructor is from_vault"
        );
        assert!(
            credentials_src.contains("#[cfg(any(test, feature = \"test-support\"))]")
                && credentials_src.contains("pub fn open(path: PathBuf)"),
            "path-open must stay cfg-gated so production cannot recreate credentials.json"
        );
        // Split the needle so this assertion does not match itself.
        let vault_save_writes_json = credentials_src.lines().any(|line| {
            let trimmed = line.trim();
            trimmed.contains("CredentialBackend::Vault")
                && trimmed.contains("write_credential_file_atomic")
        }) || credentials_src.contains(&format!(
            "{}{}",
            "write_credential_file_atomic(&self.", "path"
        ));
        assert!(
            !vault_save_writes_json,
            "vault save must not write the JSON path"
        );
        let flycockpit_src = include_str!("../../../apps/cli/src/commands/flycockpit.rs");
        assert!(
            !flycockpit_src.contains("store_credential_via_daemon_or_direct"),
            "Flycockpit direct-file fallback must be gone"
        );
        assert!(
            !flycockpit_src.contains("falling back to direct credential file write"),
            "Flycockpit must fail closed instead of writing credentials.json"
        );
    }
}
