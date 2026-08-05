//! Platform-agnostic native item adapter used by the secure-key actor.

use super::error::SecureKeyError;
use super::key_material::TempSecret;

/// Injected native store seam. Production uses keyring-core Entry against the
/// process default store; tests inject fakes and never touch the real OS store.
pub trait NativeKeyStore: Send + Sync {
    fn set_secret(&self, service: &str, account: &str, secret: &[u8])
    -> Result<(), SecureKeyError>;

    fn get_secret(&self, service: &str, account: &str) -> Result<TempSecret, SecureKeyError>;

    /// Delete; missing item is success (idempotent verify-absent).
    fn delete_secret(&self, service: &str, account: &str) -> Result<(), SecureKeyError>;
}

/// Production adapter: uses keyring_core::Entry against the default store.
pub struct KeyringNativeStore;

impl NativeKeyStore for KeyringNativeStore {
    fn set_secret(
        &self,
        service: &str,
        account: &str,
        secret: &[u8],
    ) -> Result<(), SecureKeyError> {
        let entry =
            keyring_core::Entry::new(service, account).map_err(super::error::map_keyring_error)?;
        entry
            .set_secret(secret)
            .map_err(super::error::map_keyring_error)
    }

    fn get_secret(&self, service: &str, account: &str) -> Result<TempSecret, SecureKeyError> {
        let entry =
            keyring_core::Entry::new(service, account).map_err(super::error::map_keyring_error)?;
        let bytes = entry
            .get_secret()
            .map_err(super::error::map_keyring_error)?;
        Ok(TempSecret::from_vec(bytes))
    }

    fn delete_secret(&self, service: &str, account: &str) -> Result<(), SecureKeyError> {
        let entry =
            keyring_core::Entry::new(service, account).map_err(super::error::map_keyring_error)?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(e) => Err(super::error::map_keyring_error(e)),
        }
    }
}

/// Explicit adapter for unsupported targets.
#[allow(dead_code)]
pub struct UnsupportedNativeStore;

impl NativeKeyStore for UnsupportedNativeStore {
    fn set_secret(
        &self,
        _service: &str,
        _account: &str,
        _secret: &[u8],
    ) -> Result<(), SecureKeyError> {
        Err(SecureKeyError::Unavailable(
            "native secure key store unsupported on this target".into(),
        ))
    }

    fn get_secret(&self, _service: &str, _account: &str) -> Result<TempSecret, SecureKeyError> {
        Err(SecureKeyError::Unavailable(
            "native secure key store unsupported on this target".into(),
        ))
    }

    fn delete_secret(&self, _service: &str, _account: &str) -> Result<(), SecureKeyError> {
        Err(SecureKeyError::Unavailable(
            "native secure key store unsupported on this target".into(),
        ))
    }
}
