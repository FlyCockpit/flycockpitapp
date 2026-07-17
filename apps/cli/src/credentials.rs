#![allow(dead_code)]
//! Credential storage at `$XDG_STATE_HOME/cockpit/credentials.json`
//! (defaulting to `~/.local/state/cockpit/credentials.json`).
//!
//! Why `state` rather than `share`: an auth token is mutable runtime
//! data the program can regenerate (re-login, refresh). `~/.local/share`
//! is for application data files the program does not regenerate.
//!
//! On Unix the file is created with mode `0600`. Provider records retain their
//! historical top-level shape; named secrets live under the reserved
//! `$secrets` object. Every mutation is a locked read-modify-write transaction
//! followed by an atomic replace, so independently opened stores cannot erase
//! one another's OAuth, account, API-key, or named-secret updates.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

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

pub struct CredentialStore {
    path: PathBuf,
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
    pub fn open(path: PathBuf) -> Result<Self> {
        ensure_parent_dir_private(&path)?;
        let data = read_credential_file(&path)?;
        Ok(Self {
            path,
            records: data.records,
            secrets: data.secrets,
            record_mutations: Vec::new(),
            secret_mutations: Vec::new(),
        })
    }

    pub fn open_default() -> Result<Self> {
        let path = default_path().context("could not locate $HOME for credentials path")?;
        Self::open(path)
    }

    /// Open the credential store without creating parent directories, lock
    /// files, or repairing permissions. Intended for read-only diagnostics.
    pub fn open_readonly(path: PathBuf) -> Result<Self> {
        let data = read_credential_file_readonly(&path)?;
        Ok(Self {
            path,
            records: data.records,
            secrets: data.secrets,
            record_mutations: Vec::new(),
            secret_mutations: Vec::new(),
        })
    }

    pub fn open_default_readonly() -> Result<Self> {
        let path = default_path().context("could not locate $HOME for credentials path")?;
        Self::open_readonly(path)
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

    pub fn list_named_secrets(&self) -> Vec<String> {
        self.secrets.keys().cloned().collect()
    }

    pub(crate) fn named_secret_entries(&self) -> impl Iterator<Item = (&str, &str)> {
        self.secrets
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }

    pub fn save(&mut self) -> Result<()> {
        ensure_parent_dir_private(&self.path)?;
        let _lock = lock_credential_file(&self.path)?;
        let mut latest = read_credential_file(&self.path)?;
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
        write_credential_file_atomic(&self.path, &latest)?;
        self.records = latest.records;
        self.secrets = latest.secrets;
        self.record_mutations.clear();
        self.secret_mutations.clear();
        Ok(())
    }

    pub fn save_record_merged(&self, provider_id: &str, value: Value) -> Result<()> {
        let mut latest = Self::open(self.path.clone())?;
        latest.set(provider_id, value);
        latest.save()
    }

    pub fn remove_record_merged(&self, provider_id: &str) -> Result<()> {
        let mut latest = Self::open(self.path.clone())?;
        latest.remove(provider_id);
        latest.save()
    }

    pub fn path(&self) -> &Path {
        &self.path
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
    if !path.exists() {
        return Ok(CredentialFile::default());
    }
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
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
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening credential lock {}", path.display()))?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))?;
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
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let pretty = serde_json::to_string_pretty(data)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating credential temp file in {}", parent.display()))?;
    set_temp_file_private(temp.as_file(), temp.path())?;
    temp.write_all(pretty.as_bytes())?;
    temp.as_file_mut().write_all(b"\n")?;
    temp.as_file_mut().flush()?;
    temp.as_file().sync_all()?;
    temp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("atomically replacing {}", path.display()))?;
    repair_existing_file_permissions(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_temp_file_private(file: &std::fs::File, path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))
}

#[cfg(not(unix))]
fn set_temp_file_private(_file: &std::fs::File, _path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn ensure_parent_dir_private(path: &Path) -> Result<()> {
    crate::private_fs::ensure_parent_dir_private(path)
}

#[cfg(not(unix))]
fn ensure_parent_dir_private(path: &Path) -> Result<()> {
    crate::private_fs::ensure_parent_dir_private(path)
}

#[cfg(unix)]
fn repair_existing_file_permissions(path: &Path) -> Result<()> {
    crate::private_fs::repair_private_file(path, "credential")
}

#[cfg(not(unix))]
fn repair_existing_file_permissions(_path: &Path) -> Result<()> {
    // Non-Unix platforms do not expose POSIX mode bits; credential protection
    // follows the platform filesystem defaults.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_env::lock()
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
        let _env = env_lock();
        // Each test process is independent w/ respect to env vars in
        // single-threaded mode; cargo test multithreads so we just
        // observe the result rather than relying on a stable value.
        unsafe {
            std::env::set_var("XDG_STATE_HOME", tmp.path());
        }
        let path = default_path().unwrap();
        assert!(path.starts_with(tmp.path()));
        unsafe {
            std::env::remove_var("XDG_STATE_HOME");
        }
    }
}
