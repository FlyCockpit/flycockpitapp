//! Production [`RedactionKeyResolver`] backed by the native secure-key actor.
//!
//! The secure-key actor API is async-only. This resolver holds a cloneable
//! [`SecureKeyHandle`] (enqueue-only) plus an internal cache of
//! `version -> root key`. The async `ensure_*` methods load key material from
//! the actor and warm the cache; the sync `resolve` / `active_version` are
//! cache-only so they never enqueue actor work or block a Tokio worker / the DB
//! writer thread. Callers `ensure_*` before entering a sync `Db` callback.
//!
//! Keys are cached as the 32-byte store root; the crypto layer derives
//! domain-separated encryption / fingerprint subkeys from it per use.

use std::collections::HashMap;
use std::sync::RwLock;

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crate::secure_key::{REDACTION_HISTORY_V1_NAMESPACE, SecureKeyHandle};

use super::protected_redaction_history::{
    REDACTION_KEY_LEN, RedactionHistoryKey, RedactionKeyResolver,
};

/// Production key resolver for protected redaction history. Cloneable via the
/// handle; construct one and share it (`Arc`) so every consumer shares the cache.
pub struct SecureKeyResolver {
    handle: SecureKeyHandle,
    cache: RwLock<HashMap<i64, Zeroizing<[u8; REDACTION_KEY_LEN]>>>,
    active: RwLock<Option<i64>>,
}

impl SecureKeyResolver {
    /// Build a resolver over the daemon's secure-key handle.
    pub fn new(handle: SecureKeyHandle) -> Self {
        Self {
            handle,
            cache: RwLock::new(HashMap::new()),
            active: RwLock::new(None),
        }
    }

    fn store_key(&self, version: i64, bytes: &[u8; REDACTION_KEY_LEN]) {
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(version, Zeroizing::new(*bytes));
        }
    }
}

#[async_trait::async_trait]
impl RedactionKeyResolver for SecureKeyResolver {
    async fn ensure_active(&self) -> Result<i64> {
        let (version, bytes) = self
            .handle
            .create_or_load(REDACTION_HISTORY_V1_NAMESPACE)
            .await
            .with_context(|| "loading active protected redaction-history key")?;
        self.store_key(version, bytes.as_array());
        if let Ok(mut active) = self.active.write() {
            *active = Some(version);
        }
        Ok(version)
    }

    async fn ensure_version(&self, version: i64) -> Result<()> {
        if self
            .cache
            .read()
            .map(|c| c.contains_key(&version))
            .unwrap_or(false)
        {
            return Ok(());
        }
        let (loaded, bytes) = self
            .handle
            .load_version(REDACTION_HISTORY_V1_NAMESPACE, version)
            .await
            .with_context(|| {
                format!("loading protected redaction-history key version {version}")
            })?;
        self.store_key(loaded, bytes.as_array());
        Ok(())
    }

    fn resolve(&self, version: i64) -> Result<RedactionHistoryKey> {
        let cache = self
            .cache
            .read()
            .map_err(|_| anyhow::anyhow!("redaction key cache poisoned"))?;
        let root = cache.get(&version).with_context(|| {
            format!("redaction key version {version} not cached; call ensure_version first")
        })?;
        Ok(RedactionHistoryKey::new(**root, version))
    }

    fn active_version(&self) -> Result<i64> {
        let guard = self
            .active
            .read()
            .map_err(|_| anyhow::anyhow!("redaction key active-version lock poisoned"))?;
        (*guard).context("no active redaction key version; call ensure_active first")
    }
}
