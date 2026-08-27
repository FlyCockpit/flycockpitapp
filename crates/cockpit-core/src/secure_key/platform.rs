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

/// Shared keyring probe used by the daemon capability snapshot and later by
/// `sqlite-native-key-store`. Boot and refresh must call this function; they
/// must not treat [`set_default_platform_store`] as a second independent
/// probe. Safe to call before the secure-key actor starts.
///
/// Construction is cached in-process. A later call returns the cached result
/// unless [`probe_platform_keyring_refresh`] is used. On failure the process
/// default store is unset so a failed construct cannot leak a registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyringProbeResult {
    pub state: cockpit_proto::FeatureCapabilityState,
    pub reason: String,
    pub fix_command: Option<String>,
    pub remedy_text: Option<String>,
}

struct KeyringProbeCache {
    result: Option<KeyringProbeResult>,
    construct_count: usize,
}

static KEYRING_PROBE_CACHE: Mutex<KeyringProbeCache> = Mutex::new(KeyringProbeCache {
    result: None,
    construct_count: 0,
});

/// Probe whether a platform keyring store can be constructed for one wrapping KEK.
pub fn probe_platform_keyring() -> KeyringProbeResult {
    if std::env::var_os("COCKPIT_TEST_NO_KEYRING").is_some() {
        return KeyringProbeResult {
            state: cockpit_proto::FeatureCapabilityState::Missing,
            reason: "COCKPIT_TEST_NO_KEYRING: tests must not use the host OS keyring".into(),
            fix_command: None,
            remedy_text: None,
        };
    }
    probe_platform_keyring_with(production_or_test_construct, false)
}

/// Re-run the platform keyring construct, replacing the cached result.
pub fn probe_platform_keyring_refresh() -> KeyringProbeResult {
    probe_platform_keyring_with(production_or_test_construct, true)
}

fn production_or_test_construct() -> Result<(), SecureKeyError> {
    #[cfg(test)]
    {
        // Unit tests inject via [`probe_platform_keyring_with`]. The default
        // construct never opens a real session bus.
        Err(SecureKeyError::Unavailable(
            "test default: inject probe_platform_keyring_with".into(),
        ))
    }
    #[cfg(not(test))]
    {
        set_default_platform_store()
    }
}

/// Injectable construct seam. Tests pass a fake construct; production uses
/// [`set_default_platform_store`].
pub fn probe_platform_keyring_with(
    construct: impl FnOnce() -> Result<(), SecureKeyError>,
    refresh: bool,
) -> KeyringProbeResult {
    {
        let cache = KEYRING_PROBE_CACHE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !refresh && let Some(result) = cache.result.clone() {
            return result;
        }
    }
    let result = run_keyring_construct(construct);
    let mut cache = KEYRING_PROBE_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.construct_count = cache.construct_count.saturating_add(1);
    cache.result = Some(result.clone());
    result
}

fn run_keyring_construct(
    construct: impl FnOnce() -> Result<(), SecureKeyError>,
) -> KeyringProbeResult {
    // Refresh can run after the secure-key actor has registered the live
    // process-global store. Capture it first, then restore so a dry probe
    // never leaves the actor pointing at an unset or probe-owned default.
    let previous = keyring_core::get_default_store();
    let outcome = construct();
    match &outcome {
        Ok(()) => {
            // The probe thread is short-lived. Never leave a Secret Service
            // store it constructed as the process default — zbus connections
            // do not survive that thread's exit. The actor reconstructs on
            // `cockpit-keyring-io`. Restore any store the actor already owned.
            if let Some(previous) = previous {
                keyring_core::set_default_store(previous);
            } else {
                unset_default_platform_store();
            }
        }
        Err(_) => {
            if let Some(previous) = previous {
                keyring_core::set_default_store(previous);
            } else {
                unset_default_platform_store();
            }
        }
    }
    match outcome {
        Ok(()) => KeyringProbeResult {
            state: cockpit_proto::FeatureCapabilityState::Available,
            reason: "platform keyring can hold a wrapping key".into(),
            fix_command: None,
            remedy_text: None,
        },
        Err(error) => classify_keyring_error(&error),
    }
}

fn classify_keyring_error(error: &SecureKeyError) -> KeyringProbeResult {
    use cockpit_proto::FeatureCapabilityState;
    let reason = error.to_string();
    let (state, fix_command, remedy_text) = match error {
        SecureKeyError::Unavailable(message)
            if message.contains("no native") || message.contains("unsupported") =>
        {
            (
                FeatureCapabilityState::Unsupported,
                None,
                Some("This platform has no OS keyring backend.".into()),
            )
        }
        SecureKeyError::Unavailable(message) if message.contains("DBUS_SESSION_BUS_ADDRESS") => (
            FeatureCapabilityState::Missing,
            None,
            Some(
                "Set DBUS_SESSION_BUS_ADDRESS and run a Secret Service implementation such as gnome-keyring."
                    .into(),
            ),
        ),
        SecureKeyError::Unavailable(_) | SecureKeyError::NotFound(_) => (
            FeatureCapabilityState::Missing,
            None,
            Some(keyring_missing_remedy_text()),
        ),
        _ => (
            FeatureCapabilityState::Failed,
            None,
            Some(keyring_missing_remedy_text()),
        ),
    };
    KeyringProbeResult {
        state,
        reason,
        fix_command,
        remedy_text,
    }
}

fn keyring_missing_remedy_text() -> String {
    "Install a platform keyring (Linux Secret Service, macOS Keychain, or Windows Credential Manager) and ensure a session bus is available.".into()
}

#[cfg(test)]
pub fn keyring_probe_construct_count() -> usize {
    KEYRING_PROBE_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .construct_count
}

#[cfg(test)]
pub fn reset_keyring_probe_cache_for_test() {
    let mut cache = KEYRING_PROBE_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.result = None;
    cache.construct_count = 0;
}

#[cfg(test)]
pub fn default_platform_store_is_registered() -> bool {
    keyring_core::get_default_store().is_some()
}

/// Construct the process default store and register it. Call before accepting
/// secure-key requests on the production path.
///
/// Not a capability probe. Callers that need availability must use
/// [`probe_platform_keyring`] so boot/refresh share one construct.
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
        // Store::new uses zbus's blocking Connection::session, which creates a
        // nested Tokio runtime. Always construct off-thread so doctor, daemon
        // boot, and IsolatedHome mock buses never nest.
        construct_linux_secret_service_store()
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Err(SecureKeyError::Unavailable(
            "no native secure key store on this target".into(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn construct_linux_secret_service_store() -> Result<(), SecureKeyError> {
    fn construct() -> Result<(), SecureKeyError> {
        let store = zbus_secret_service_keyring_store::Store::new()
            .map_err(|e| SecureKeyError::Unavailable(format!("secret service store: {e}")))?;
        keyring_core::set_default_store(store);
        Ok(())
    }
    std::thread::Builder::new()
        .name("cockpit-keyring-construct".into())
        .spawn(construct)
        .map_err(|e| SecureKeyError::Unavailable(format!("keyring construct thread: {e}")))?
        .join()
        .unwrap_or_else(|_| {
            Err(SecureKeyError::Unavailable(
                "keyring construct thread panicked".into(),
            ))
        })
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
