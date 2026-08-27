//! Platform-agnostic native item adapter used by the secure-key actor.

use zeroize::Zeroizing;

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

    /// Diagnostic enumeration of accounts under `service` when the adapter supports it.
    /// Used only to detect unexpected third sealed-state accounts; never to load state.
    /// Default: empty (adapter cannot enumerate).
    fn list_accounts(&self, _service: &str) -> Result<Vec<String>, SecureKeyError> {
        Ok(Vec::new())
    }
}

/// Production adapter: uses keyring_core::Entry against the default store.
pub struct KeyringNativeStore;

/// zbus's blocking Secret Service API calls `block_on`. That panics on a
/// Tokio worker (daemon boot, `DaemonContext::new`, vault first-run). Run
/// the entry op on a dedicated thread whenever a runtime is already active.
fn with_keyring_off_runtime<T, F>(op: F) -> Result<T, SecureKeyError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, SecureKeyError> + Send + 'static,
{
    if tokio::runtime::Handle::try_current().is_ok() {
        return std::thread::Builder::new()
            .name("cockpit-keyring-io".into())
            .spawn(op)
            .map_err(|e| SecureKeyError::Unavailable(format!("keyring io thread: {e}")))?
            .join()
            .unwrap_or_else(|_| {
                Err(SecureKeyError::Unavailable(
                    "keyring io thread panicked".into(),
                ))
            });
    }
    op()
}

impl NativeKeyStore for KeyringNativeStore {
    fn set_secret(
        &self,
        service: &str,
        account: &str,
        secret: &[u8],
    ) -> Result<(), SecureKeyError> {
        let service = service.to_owned();
        let account = account.to_owned();
        let secret = Zeroizing::new(secret.to_vec());
        with_keyring_off_runtime(move || {
            let entry = keyring_core::Entry::new(&service, &account)
                .map_err(super::error::map_keyring_error)?;
            entry
                .set_secret(&secret)
                .map_err(super::error::map_keyring_error)
        })
    }

    fn get_secret(&self, service: &str, account: &str) -> Result<TempSecret, SecureKeyError> {
        let service = service.to_owned();
        let account = account.to_owned();
        with_keyring_off_runtime(move || {
            let entry = keyring_core::Entry::new(&service, &account)
                .map_err(super::error::map_keyring_error)?;
            let bytes = entry
                .get_secret()
                .map_err(super::error::map_keyring_error)?;
            Ok(TempSecret::from_vec(bytes))
        })
    }

    fn delete_secret(&self, service: &str, account: &str) -> Result<(), SecureKeyError> {
        let service = service.to_owned();
        let account = account.to_owned();
        with_keyring_off_runtime(move || {
            let entry = keyring_core::Entry::new(&service, &account)
                .map_err(super::error::map_keyring_error)?;
            match entry.delete_credential() {
                Ok(()) => Ok(()),
                Err(keyring_core::Error::NoEntry) => Ok(()),
                Err(e) => Err(super::error::map_keyring_error(e)),
            }
        })
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
