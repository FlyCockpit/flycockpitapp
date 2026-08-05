//! Target store construction, process-global registration, and cfg inventory.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::error::SecureKeyError;
use super::native_store::NativeKeyStore;

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use super::native_store::KeyringNativeStore;
#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
use super::native_store::UnsupportedNativeStore;

/// Which native store crate is reachable on this compile target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformStoreKind {
    AppleKeychain,
    WindowsCredentialManager,
    ZbusSecretService,
    Unsupported,
}

/// cfg compile inventory for acceptance criterion 11/12.
pub const fn platform_store_kind() -> PlatformStoreKind {
    #[cfg(target_os = "macos")]
    {
        PlatformStoreKind::AppleKeychain
    }
    #[cfg(target_os = "windows")]
    {
        PlatformStoreKind::WindowsCredentialManager
    }
    #[cfg(target_os = "linux")]
    {
        PlatformStoreKind::ZbusSecretService
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        PlatformStoreKind::Unsupported
    }
}

/// Crate name of the one reachable native store (or none on Unsupported).
pub fn reachable_native_store_crate() -> Option<&'static str> {
    match platform_store_kind() {
        PlatformStoreKind::AppleKeychain => Some("apple-native-keyring-store"),
        PlatformStoreKind::WindowsCredentialManager => Some("windows-native-keyring-store"),
        PlatformStoreKind::ZbusSecretService => Some("zbus-secret-service-keyring-store"),
        PlatformStoreKind::Unsupported => None,
    }
}

/// Force-link symbols so cfg inventory is visible to `cargo tree` / compile.
#[cfg(target_os = "macos")]
pub fn platform_link_token() -> &'static str {
    // Reference the Store type so the crate is not DCE'd from the graph.
    let _ = std::any::type_name::<apple_native_keyring_store::keychain::Store>();
    "apple-native-keyring-store"
}

#[cfg(target_os = "windows")]
pub fn platform_link_token() -> &'static str {
    let _ = std::any::type_name::<windows_native_keyring_store::Store>();
    "windows-native-keyring-store"
}

#[cfg(target_os = "linux")]
pub fn platform_link_token() -> &'static str {
    let _ = std::any::type_name::<zbus_secret_service_keyring_store::Store>();
    "zbus-secret-service-keyring-store"
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
pub fn platform_link_token() -> &'static str {
    "unsupported"
}

// ---- Registration ordering observability (production + tests) -------------

static REG_SEQ: AtomicUsize = AtomicUsize::new(1);
static SET_DEFAULT_AT: AtomicUsize = AtomicUsize::new(0);
static ACTOR_INTAKE_AT: AtomicUsize = AtomicUsize::new(0);
static DRAIN_COMPLETE_AT: AtomicUsize = AtomicUsize::new(0);
static UNSET_DEFAULT_AT: AtomicUsize = AtomicUsize::new(0);
static TEST_SKIP_REAL_DEFAULT: AtomicBool = AtomicBool::new(false);
/// Thread name observed during the last `set_default_platform_store` call (tests).
static SET_DEFAULT_THREAD_NAME: Mutex<Option<String>> = Mutex::new(None);

fn next_seq() -> usize {
    REG_SEQ.fetch_add(1, Ordering::SeqCst)
}

/// Snapshot of registration lifecycle sequence numbers (0 = not yet observed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistrationOrderSnapshot {
    pub set_default_at: usize,
    pub actor_intake_at: usize,
    pub drain_complete_at: usize,
    pub unset_default_at: usize,
}

pub fn registration_order_snapshot() -> RegistrationOrderSnapshot {
    RegistrationOrderSnapshot {
        set_default_at: SET_DEFAULT_AT.load(Ordering::SeqCst),
        actor_intake_at: ACTOR_INTAKE_AT.load(Ordering::SeqCst),
        drain_complete_at: DRAIN_COMPLETE_AT.load(Ordering::SeqCst),
        unset_default_at: UNSET_DEFAULT_AT.load(Ordering::SeqCst),
    }
}

pub fn reset_registration_order_for_test() {
    SET_DEFAULT_AT.store(0, Ordering::SeqCst);
    ACTOR_INTAKE_AT.store(0, Ordering::SeqCst);
    DRAIN_COMPLETE_AT.store(0, Ordering::SeqCst);
    UNSET_DEFAULT_AT.store(0, Ordering::SeqCst);
    REG_SEQ.store(1, Ordering::SeqCst);
    if let Ok(mut g) = SET_DEFAULT_THREAD_NAME.lock() {
        *g = None;
    }
}

/// When true, [`set_default_platform_store`] records order only (no real OS store).
pub fn set_test_skip_real_default_store(skip: bool) {
    TEST_SKIP_REAL_DEFAULT.store(skip, Ordering::SeqCst);
}

/// Thread name of the last `set_default_platform_store` (for production-path tests).
#[allow(dead_code)] // used from unit tests
pub fn last_set_default_thread_name() -> Option<String> {
    SET_DEFAULT_THREAD_NAME.lock().ok().and_then(|g| g.clone())
}

pub(crate) fn mark_actor_intake_ready() {
    ACTOR_INTAKE_AT.store(next_seq(), Ordering::SeqCst);
}

pub(crate) fn mark_worker_drained() {
    DRAIN_COMPLETE_AT.store(next_seq(), Ordering::SeqCst);
}

/// Construct the process default store and register it. Call before accepting
/// secure-key requests on the production path.
pub(crate) fn set_default_platform_store() -> Result<(), SecureKeyError> {
    SET_DEFAULT_AT.store(next_seq(), Ordering::SeqCst);
    if let Ok(mut g) = SET_DEFAULT_THREAD_NAME.lock() {
        *g = std::thread::current().name().map(|s| s.to_owned());
    }
    if TEST_SKIP_REAL_DEFAULT.load(Ordering::SeqCst) {
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        let store = apple_native_keyring_store::keychain::Store::new()
            .map_err(|e| SecureKeyError::Unavailable(format!("apple keychain store: {e}")))?;
        keyring_core::set_default_store(store);
        return Ok(());
    }
    #[cfg(target_os = "windows")]
    {
        let store = windows_native_keyring_store::Store::new()
            .map_err(|e| SecureKeyError::Unavailable(format!("windows credential store: {e}")))?;
        keyring_core::set_default_store(store);
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        // Fail fast when no session bus is configured rather than blocking
        // indefinitely inside Store::new (keeps construction on this actor
        // thread; no helper thread).
        if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
            return Err(SecureKeyError::Unavailable(
                "DBUS_SESSION_BUS_ADDRESS unset; secret service unavailable".into(),
            ));
        }
        let store = zbus_secret_service_keyring_store::Store::new()
            .map_err(|e| SecureKeyError::Unavailable(format!("secret service store: {e}")))?;
        keyring_core::set_default_store(store);
        Ok(())
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Err(SecureKeyError::Unavailable(
            "no native secure key store on this target".into(),
        ))
    }
}

pub(crate) fn unset_default_platform_store() {
    UNSET_DEFAULT_AT.store(next_seq(), Ordering::SeqCst);
    if TEST_SKIP_REAL_DEFAULT.load(Ordering::SeqCst) {
        return;
    }
    keyring_core::unset_default_store();
}

/// Production native adapter (uses process default store).
pub fn production_native_store() -> Box<dyn NativeKeyStore> {
    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    {
        Box::new(KeyringNativeStore)
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Box::new(UnsupportedNativeStore)
    }
}
