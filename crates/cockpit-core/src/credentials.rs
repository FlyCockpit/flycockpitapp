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

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use cockpit_db::secret_vault::SecretVaultKind;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::secure_key::SecretVault;

#[cfg(any(test, feature = "test-support"))]
include!("credentials_test_open.rs");

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

#[derive(Clone)]
enum CredentialBackend {
    Vault(Arc<SecretVault>),
    #[cfg(any(test, feature = "test-support"))]
    LegacyFile {
        path: PathBuf,
    },
}

#[derive(Clone)]
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

    /// Owner-scoped resolution constructor (named-secret ownership boundary).
    ///
    /// Builds a vault-backed store whose named-secret view is restricted to the
    /// secrets the referencing context `(owner_kind, project_root)` may resolve:
    /// every name already owned by this context, plus any legacy (unclaimed)
    /// name the config actually references that is prefix-legitimate for this
    /// kind — those are atomically backfilled to this owner and then resolve.
    /// A name owned by a DIFFERENT (kind, root) is dropped from the view, so a
    /// `$secret:NAME` reference in a config owned by A can never resolve a secret
    /// owned by B: `named_secret` returns `None` and the resolver fails closed
    /// (it never forwards a literal). See [`crate::secret_ownership`].
    ///
    /// `referenced_names` is the set of named-secret ids the config references
    /// (provider `$secret:` header names, or MCP credential/OAuth keys). Only
    /// these are eligible for legacy backfill, so a construction never claims a
    /// name the context does not actually use.
    ///
    /// `foreign_scope_references` gates legacy backfill against first-resolver-
    /// steals (gap 4): `None` when sole-ownership is UNPROVABLE at this boundary
    /// (session/MCP/policy resolution have no cross-config scan) — then no legacy
    /// name is ever claimed and an unclaimed reference fails closed; `Some(set)`
    /// when the daemon scanned every other known config and `set` holds the names
    /// referenced under a DIFFERENT `(kind, root)`, so a referenced unclaimed name
    /// is claimed only when it is the sole eligible owner. See
    /// [`crate::secret_ownership::scope_named_secret_ownership`].
    ///
    /// The credential `records` view is scoped by the `secret_credential_ownership`
    /// table too (gap 2): a record owned only by a DIFFERENT workspace is dropped
    /// so the MCP resolver's record fallback cannot reach a foreign-owned
    /// `mcp:<server>` blob. Unclaimed (legacy) and same-owner records still
    /// resolve, preserving configure-then-authenticate and the never-claimed
    /// Flycockpit global-account credential.
    pub fn from_vault_owner_scoped(
        vault: Arc<SecretVault>,
        owner_kind: &str,
        project_root: &str,
        referenced_names: &BTreeSet<String>,
        foreign_scope_references: Option<&BTreeSet<String>>,
    ) -> Result<Self> {
        let (all_records, all_secrets) = load_from_vault(&vault)?;
        let present: BTreeSet<String> = all_secrets.keys().cloned().collect();
        let scoped_names = crate::secret_ownership::scope_named_secret_ownership(
            vault.db(),
            owner_kind,
            project_root,
            &present,
            referenced_names,
            foreign_scope_references,
        )?;
        let secrets = all_secrets
            .into_iter()
            .filter(|(name, _)| scoped_names.contains(name))
            .collect();
        let present_records: BTreeSet<String> = all_records.keys().cloned().collect();
        let scoped_records = crate::secret_ownership::scope_credential_records(
            vault.db(),
            project_root,
            &present_records,
        )?;
        let records = all_records
            .into_iter()
            .filter(|(id, _)| scoped_records.contains(id))
            .collect();
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

    /// Read a leftover `credentials.json` for test fixtures only.
    #[cfg(any(test, feature = "test-support"))]
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

    /// Settings/test fixtures pass an explicit leftover JSON path. Production
    /// construction with `None` is not a product API.
    #[cfg(any(test, feature = "test-support"))]
    pub fn open_for_path_or_default(path: Option<&Path>) -> Result<Self> {
        if let Some(path) = path {
            return Self::open(path.to_path_buf());
        }
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

    /// Return every string leaf in a provider credential record.
    ///
    /// Provider records are opaque JSON owned by integrations. The narrower
    /// [`provider_credential_entries`] inventory is appropriate for building
    /// the long-lived general redaction table, but response scrubbers must
    /// also cover credentials stored under provider-specific, non-secret
    /// field names. Keeping this traversal separate prevents metadata from
    /// becoming a broadly redacted candidate while still stopping a provider
    /// from reflecting any string held in its credential record.
    pub(crate) fn provider_credential_leaf_entries(
        &self,
    ) -> impl Iterator<Item = (String, String)> {
        let mut entries = Vec::new();
        for (provider, record) in &self.records {
            collect_string_leaves(record, &format!("$credentials:{provider}"), &mut entries);
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
            #[cfg(any(test, feature = "test-support"))]
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

    /// Persist one named secret through the daemon owner-mutation seam. MCP
    /// token refreshes use this instead of `save`: the vault publishes the
    /// active redaction table immediately and compensates the write if that
    /// publication fails.
    pub fn set_named_secret_and_save_published(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<()> {
        let name = name.into();
        let value = value.into();
        match &self.backend {
            CredentialBackend::Vault(vault) => {
                vault
                    .mutate_owner_item(SecretVaultKind::NamedSecret, &name, Some(value.as_bytes()))
                    .map_err(|error| anyhow::anyhow!(error))?;
                self.secrets.insert(name, value);
                self.record_mutations.clear();
                self.secret_mutations.clear();
                Ok(())
            }
            #[cfg(any(test, feature = "test-support"))]
            CredentialBackend::LegacyFile { .. } => {
                self.set_named_secret(name, value);
                self.save()
            }
        }
    }

    /// Persist one named secret through the daemon owner-mutation seam, enforcing
    /// the in-transaction ownership guard: the write fails closed if the name is
    /// owned by a different (`owner_kind`, `project_root`). Used by MCP OAuth
    /// token refresh so a refresh must own the name it rotates (a foreign-owned
    /// name is never mutated). See [`crate::secret_ownership`].
    pub fn set_named_secret_owned_and_save_published(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
        owner_kind: &str,
        project_root: &str,
    ) -> Result<()> {
        let name = name.into();
        let value = value.into();
        match &self.backend {
            CredentialBackend::Vault(vault) => {
                vault
                    .mutate_owner_named_secret_guarded(
                        &name,
                        value.as_bytes(),
                        owner_kind,
                        project_root,
                    )
                    .map_err(|error| anyhow::anyhow!(error))?;
                self.secrets.insert(name, value);
                self.record_mutations.clear();
                self.secret_mutations.clear();
                Ok(())
            }
            #[cfg(any(test, feature = "test-support"))]
            CredentialBackend::LegacyFile { .. } => {
                self.set_named_secret(name, value);
                self.save()
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
            #[cfg(any(test, feature = "test-support"))]
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
            #[cfg(any(test, feature = "test-support"))]
            CredentialBackend::LegacyFile { path } => {
                let mut latest = Self::open_legacy_file(path.clone())?;
                latest.remove(provider_id);
                latest.save()
            }
        }
    }

    pub fn path(&self) -> &Path {
        match &self.backend {
            #[cfg(any(test, feature = "test-support"))]
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
            #[cfg(any(test, feature = "test-support"))]
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

fn collect_string_leaves(value: &Value, origin: &str, out: &mut Vec<(String, String)>) {
    match value {
        Value::String(value) => out.push((origin.to_string(), value.clone())),
        Value::Object(fields) => {
            for (key, value) in fields {
                collect_string_leaves(value, &format!("{origin}.{key}"), out);
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                collect_string_leaves(value, &format!("{origin}[{index}]"), out);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
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

    fn vault_backed() -> (crate::db::Db, Arc<SecretVault>) {
        let db = crate::db::Db::open_in_memory().unwrap();
        let vault = crate::secure_key::open_for_db(&db).unwrap();
        (db, vault)
    }

    fn put_named(vault: &Arc<SecretVault>, name: &str, value: &str) {
        let mut store = CredentialStore::from_vault(vault.clone()).unwrap();
        store.set_named_secret(name, value);
        store.save().unwrap();
    }

    fn insert_ownership(db: &crate::db::Db, item_id: &str, owner_kind: &str, project_root: &str) {
        let item_id = item_id.to_string();
        let owner_kind = owner_kind.to_string();
        let project_root = project_root.to_string();
        db.blocking_write_for_sync_maintenance(move |conn| {
            conn.execute(
                "INSERT INTO secret_named_ownership (item_id, owner_kind, project_root, created_at)
                 VALUES (?1, ?2, ?3, 0)",
                rusqlite::params![item_id, owner_kind, project_root],
            )?;
            Ok(())
        })
        .unwrap();
    }

    fn insert_credential_ownership(
        db: &crate::db::Db,
        item_id: &str,
        provider_id: &str,
        project_root: &str,
    ) {
        let item_id = item_id.to_string();
        let provider_id = provider_id.to_string();
        let project_root = project_root.to_string();
        db.blocking_write_for_sync_maintenance(move |conn| {
            conn.execute(
                "INSERT INTO secret_credential_ownership (item_id, provider_id, project_root, created_at)
                 VALUES (?1, ?2, ?3, 0)",
                rusqlite::params![item_id, provider_id, project_root],
            )?;
            Ok(())
        })
        .unwrap();
    }

    fn ownership_exists(
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

    // Gap 1: owner-scoped resolution. A `$secret:` owned by (provider, A) resolves
    // ONLY in its owning context — not in an (mcp, A) or (provider, B) context.
    #[test]
    fn owner_scoped_store_resolves_only_owning_context() {
        let (db, vault) = vault_backed();
        put_named(&vault, "openai", "sk-provider-owned");
        insert_ownership(&db, "openai", "provider", "/ws/a");
        let referenced = BTreeSet::from(["openai".to_string()]);

        let owner = CredentialStore::from_vault_owner_scoped(
            vault.clone(),
            "provider",
            "/ws/a",
            &referenced,
            None,
        )
        .unwrap();
        assert_eq!(owner.named_secret("openai"), Some("sk-provider-owned"));

        let cross_kind = CredentialStore::from_vault_owner_scoped(
            vault.clone(),
            "mcp",
            "/ws/a",
            &referenced,
            None,
        )
        .unwrap();
        assert_eq!(
            cross_kind.named_secret("openai"),
            None,
            "cross-kind context must fail closed"
        );

        let cross_root = CredentialStore::from_vault_owner_scoped(
            vault.clone(),
            "provider",
            "/ws/b",
            &referenced,
            None,
        )
        .unwrap();
        assert_eq!(
            cross_root.named_secret("openai"),
            None,
            "cross-root context must fail closed"
        );
    }

    // Gap 1 + gap 4 backfill: a legacy (unclaimed) reference that this context is
    // the SOLE eligible owner of (empty foreign-reference set) resolves and is
    // atomically claimed, so a DIFFERENT context then fails closed. A SECOND
    // unclaimed secret that this config does NOT reference must NOT be claimed or
    // resolved (gap 7: the backfill is targeted, not "claim every unowned name").
    #[test]
    fn owner_scoped_store_backfills_only_sole_owned_referenced_name() {
        let (db, vault) = vault_backed();
        put_named(&vault, "legacy", "sk-legacy");
        // A distractor secret present in the vault but NOT referenced by this
        // config and never claimed by anyone.
        put_named(&vault, "unreferenced", "sk-unreferenced");
        assert!(
            !ownership_exists(&db, "legacy", "provider", "/ws/a"),
            "precondition: legacy secret is unclaimed"
        );
        let referenced = BTreeSet::from(["legacy".to_string()]);
        let no_foreign = BTreeSet::new();

        let owner = CredentialStore::from_vault_owner_scoped(
            vault.clone(),
            "provider",
            "/ws/a",
            &referenced,
            Some(&no_foreign),
        )
        .unwrap();
        assert_eq!(owner.named_secret("legacy"), Some("sk-legacy"));
        assert!(
            ownership_exists(&db, "legacy", "provider", "/ws/a"),
            "backfilled claim must persist"
        );
        // Gap 7: the unreferenced distractor must be neither resolved nor claimed.
        assert_eq!(
            owner.named_secret("unreferenced"),
            None,
            "an unreferenced secret must never enter the scoped view"
        );
        assert!(
            !ownership_exists(&db, "unreferenced", "provider", "/ws/a"),
            "backfill must not claim a name this config does not reference"
        );

        let other = CredentialStore::from_vault_owner_scoped(
            vault.clone(),
            "provider",
            "/ws/b",
            &referenced,
            Some(&no_foreign),
        )
        .unwrap();
        assert_eq!(
            other.named_secret("legacy"),
            None,
            "once backfilled to A, B must fail closed"
        );
    }

    // Gap 4: a legacy unclaimed name referenced by configs under two different
    // scopes is AMBIGUOUS — neither context may auto-claim it. It is not resolved
    // and no ownership row is written; the user must migrate explicitly.
    #[test]
    fn owner_scoped_store_does_not_steal_ambiguous_reference() {
        let (db, vault) = vault_backed();
        put_named(&vault, "shared", "sk-shared");
        let referenced = BTreeSet::from(["shared".to_string()]);
        // The daemon scan proved `shared` is ALSO referenced by a config under a
        // different root, so it is foreign-scope-ambiguous for this context.
        let foreign = BTreeSet::from(["shared".to_string()]);

        let ws_a = CredentialStore::from_vault_owner_scoped(
            vault.clone(),
            "provider",
            "/ws/a",
            &referenced,
            Some(&foreign),
        )
        .unwrap();
        assert_eq!(
            ws_a.named_secret("shared"),
            None,
            "an ambiguous name must fail closed, not be stolen"
        );
        assert!(
            !ownership_exists(&db, "shared", "provider", "/ws/a"),
            "an ambiguous name must not be claimed"
        );

        // The other referencing workspace is symmetrically blocked.
        let ws_b = CredentialStore::from_vault_owner_scoped(
            vault.clone(),
            "provider",
            "/ws/b",
            &referenced,
            Some(&foreign),
        )
        .unwrap();
        assert_eq!(ws_b.named_secret("shared"), None);
        assert!(!ownership_exists(&db, "shared", "provider", "/ws/b"));
    }

    // Gap 4: with sole-ownership UNPROVABLE (no cross-config scan available, e.g.
    // the session/MCP resolution boundary), an unclaimed legacy name is never
    // claimed and does not resolve — but an ALREADY-owned name still resolves.
    #[test]
    fn owner_scoped_store_without_scan_never_claims_but_resolves_owned() {
        let (db, vault) = vault_backed();
        put_named(&vault, "legacy", "sk-legacy");
        put_named(&vault, "owned", "sk-owned");
        insert_ownership(&db, "owned", "provider", "/ws/a");
        let referenced = BTreeSet::from(["legacy".to_string(), "owned".to_string()]);

        let store = CredentialStore::from_vault_owner_scoped(
            vault.clone(),
            "provider",
            "/ws/a",
            &referenced,
            None,
        )
        .unwrap();
        assert_eq!(
            store.named_secret("owned"),
            Some("sk-owned"),
            "an already-owned name resolves even without a scan"
        );
        assert_eq!(
            store.named_secret("legacy"),
            None,
            "an unclaimed name is not claimed when sole-ownership is unprovable"
        );
        assert!(
            !ownership_exists(&db, "legacy", "provider", "/ws/a"),
            "the no-scan boundary must never write an ownership row"
        );
    }

    // Gap 2: a credential RECORD owned for workspace A must NOT resolve for an
    // owner-scoped store built for workspace B — the MCP resolver's record
    // fallback (`store.get`) can no longer reach a foreign-owned `mcp:` blob.
    #[test]
    fn owner_scoped_store_drops_foreign_owned_record() {
        let (db, vault) = vault_backed();
        // A legacy MCP OAuth blob stored as a credential record and owned by A.
        {
            let mut store = CredentialStore::from_vault(vault.clone()).unwrap();
            store.set(
                "mcp:victim",
                serde_json::json!({ "access_token": "A-token" }),
            );
            store.save().unwrap();
        }
        insert_credential_ownership(&db, "mcp:victim", "mcp", "/ws/a");

        let referenced = BTreeSet::new();
        // Workspace B builds an MCP owner-scoped store.
        let ws_b = CredentialStore::from_vault_owner_scoped(
            vault.clone(),
            "mcp",
            "/ws/b",
            &referenced,
            None,
        )
        .unwrap();
        assert!(
            ws_b.get("mcp:victim").is_none(),
            "a record owned by workspace A must not resolve for workspace B"
        );

        // The owning workspace A still resolves it (configure-then-authenticate).
        let ws_a = CredentialStore::from_vault_owner_scoped(
            vault.clone(),
            "mcp",
            "/ws/a",
            &referenced,
            None,
        )
        .unwrap();
        assert!(
            ws_a.get("mcp:victim").is_some(),
            "the owning workspace must still resolve its own record"
        );

        // An UNCLAIMED (legacy) record resolves for any workspace — preserves the
        // never-claimed Flycockpit global-account credential.
        {
            let mut store = CredentialStore::from_vault(vault.clone()).unwrap();
            store.set("legacy-record", serde_json::json!({ "api_key": "k" }));
            store.save().unwrap();
        }
        let any = CredentialStore::from_vault_owner_scoped(
            vault.clone(),
            "provider",
            "/ws/c",
            &BTreeSet::new(),
            None,
        )
        .unwrap();
        assert!(
            any.get("legacy-record").is_some(),
            "an unclaimed legacy record must still resolve"
        );
    }

    // Gap 1: an OAuth key (`mcp:<server>`) resolves for its MCP owner; a provider
    // scope must NOT adopt an `mcp:`-prefixed name even when unclaimed.
    #[test]
    fn owner_scoped_store_oauth_key_resolves_for_mcp_owner_only() {
        let (db, vault) = vault_backed();
        put_named(&vault, "mcp:server", "oauth-token");
        let referenced = BTreeSet::from(["mcp:server".to_string()]);

        let no_foreign = BTreeSet::new();
        // Provider scope must never claim/resolve an mcp: name.
        let provider = CredentialStore::from_vault_owner_scoped(
            vault.clone(),
            "provider",
            "/ws/a",
            &referenced,
            Some(&no_foreign),
        )
        .unwrap();
        assert_eq!(provider.named_secret("mcp:server"), None);
        assert!(!ownership_exists(&db, "mcp:server", "provider", "/ws/a"));

        // The MCP owner backfills + resolves it.
        let mcp = CredentialStore::from_vault_owner_scoped(
            vault.clone(),
            "mcp",
            "/ws/a",
            &referenced,
            Some(&no_foreign),
        )
        .unwrap();
        assert_eq!(mcp.named_secret("mcp:server"), Some("oauth-token"));
        assert!(ownership_exists(&db, "mcp:server", "mcp", "/ws/a"));
    }

    // Gap 4: a guarded owner write (the funnel MCP OAuth refresh routes through)
    // fails closed against a foreign owner and never mutates the vault value.
    #[test]
    fn guarded_owner_write_rejects_foreign_owner_and_preserves_value() {
        let (db, vault) = vault_backed();
        put_named(&vault, "mcp:victim", "orig-token");
        insert_ownership(&db, "mcp:victim", "mcp", "/ws/a");
        let mut store = CredentialStore::from_vault(vault.clone()).unwrap();

        let err = store
            .set_named_secret_owned_and_save_published("mcp:victim", "stolen", "mcp", "/ws/b")
            .expect_err("a refresh from a foreign workspace must be rejected");
        let _ = err;
        let reread = CredentialStore::from_vault(vault.clone()).unwrap();
        assert_eq!(
            reread.named_secret("mcp:victim"),
            Some("orig-token"),
            "a rejected refresh must not mutate the foreign-owned value"
        );

        // The owning workspace can rotate it.
        store
            .set_named_secret_owned_and_save_published("mcp:victim", "rotated", "mcp", "/ws/a")
            .expect("the owning workspace may rotate its own token");
        let reread = CredentialStore::from_vault(vault.clone()).unwrap();
        assert_eq!(reread.named_secret("mcp:victim"), Some("rotated"));
    }

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
    fn provider_credential_leaf_entries_collect_opaque_nested_strings() {
        let tmp = TempDir::new().unwrap();
        let mut store = CredentialStore::open(tmp.path().join("credentials.json")).unwrap();
        store.set(
            "provider",
            serde_json::json!({
                "oauth": { "opaque": { "token_value": "reflected-token-123456" } },
                "account": { "id": "account-id-123456" },
                "enabled": true
            }),
        );

        let entries: Vec<_> = store.provider_credential_leaf_entries().collect();
        assert!(
            entries
                .iter()
                .any(|(_, value)| value == "reflected-token-123456")
        );
        assert!(
            entries
                .iter()
                .any(|(_, value)| value == "account-id-123456")
        );
        assert!(!entries.iter().any(|(_, value)| value == "true"));
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
