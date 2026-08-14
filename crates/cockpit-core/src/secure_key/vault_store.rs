//! NativeKeyStore adapter that persists actor items as vault AEAD rows.

use std::sync::Arc;

use cockpit_db::secret_vault::SecretVaultKind;

use super::error::SecureKeyError;
use super::key_material::TempSecret;
use super::native_store::NativeKeyStore;
use super::vault::SecretVault;

#[derive(Clone)]
pub struct VaultNativeStore {
    vault: Arc<SecretVault>,
}

impl VaultNativeStore {
    pub fn new(vault: Arc<SecretVault>) -> Self {
        Self { vault }
    }

    pub fn vault(&self) -> &Arc<SecretVault> {
        &self.vault
    }
}

impl std::fmt::Debug for VaultNativeStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultNativeStore")
            .field("vault", &self.vault)
            .finish()
    }
}

pub fn classify_account(account: &str) -> SecretVaultKind {
    if account.ends_with("/manifest") {
        SecretVaultKind::SecureKeyManifest
    } else if account.ends_with("/state-a") || account.ends_with("/state-b") {
        SecretVaultKind::SealedState
    } else {
        SecretVaultKind::SecureKeyRoot
    }
}

impl NativeKeyStore for VaultNativeStore {
    fn set_secret(
        &self,
        _service: &str,
        account: &str,
        secret: &[u8],
    ) -> Result<(), SecureKeyError> {
        self.vault
            .put_item(classify_account(account), account, secret)
    }

    fn get_secret(&self, _service: &str, account: &str) -> Result<TempSecret, SecureKeyError> {
        self.vault.get_item(classify_account(account), account)
    }

    fn delete_secret(&self, _service: &str, account: &str) -> Result<(), SecureKeyError> {
        self.vault.delete_item(classify_account(account), account)
    }

    fn list_accounts(&self, _service: &str) -> Result<Vec<String>, SecureKeyError> {
        let mut ids = Vec::new();
        for kind in [
            SecretVaultKind::SecureKeyRoot,
            SecretVaultKind::SecureKeyManifest,
            SecretVaultKind::SealedState,
        ] {
            ids.extend(self.vault.list_item_ids(kind)?);
        }
        ids.sort();
        ids.dedup();
        Ok(ids)
    }
}
