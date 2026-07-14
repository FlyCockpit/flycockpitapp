#![allow(dead_code)]
//! Credential storage at `$XDG_STATE_HOME/cockpit/credentials.json`
//! (defaulting to `~/.local/state/cockpit/credentials.json`).
//!
//! Why `state` rather than `share`: an auth token is mutable runtime
//! data the program can regenerate (re-login, refresh). `~/.local/share`
//! is for application data files the program does not regenerate.
//!
//! On Unix the file is created with mode `0600`. The file is opaque
//! JSON: `{ "<provider-id>": { ... }, ... }`. The shape of each entry
//! is per-provider — `api_key` for static keys, an OAuth bundle for
//! device-flow providers — so we store them as untyped `serde_json::Value`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
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
}

impl CredentialStore {
    pub fn open(path: PathBuf) -> Result<Self> {
        ensure_parent_dir_private(&path)?;
        let records = if path.exists() {
            repair_existing_file_permissions(&path)?;
            let raw = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            if raw.trim().is_empty() {
                BTreeMap::new()
            } else {
                serde_json::from_str::<BTreeMap<String, Value>>(&raw)
                    .with_context(|| format!("parsing {}", path.display()))?
            }
        } else {
            BTreeMap::new()
        };
        Ok(Self { path, records })
    }

    pub fn open_default() -> Result<Self> {
        let path = default_path().context("could not locate $HOME for credentials path")?;
        Self::open(path)
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
        self.records.insert(provider_id.into(), value);
    }

    pub fn set_api_key(&mut self, provider_id: impl Into<String>, key: impl Into<String>) {
        self.set(provider_id, serde_json::json!({ "api_key": key.into() }));
    }

    pub fn remove(&mut self, provider_id: &str) {
        self.records.remove(provider_id);
    }

    pub fn save(&self) -> Result<()> {
        ensure_parent_dir_private(&self.path)?;
        let pretty = serde_json::to_string_pretty(&self.records)?;
        write_with_0600(&self.path, pretty.as_bytes())?;
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

#[cfg(unix)]
fn write_with_0600(path: &Path, bytes: &[u8]) -> Result<()> {
    crate::private_fs::write_private_file(path, bytes)
}

#[cfg(not(unix))]
fn write_with_0600(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
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
