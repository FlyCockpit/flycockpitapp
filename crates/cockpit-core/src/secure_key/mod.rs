//! Daemon-owned versioned native secure key store.
//!
//! One actor thread serializes create/rotate/retire against the wrap-key vault
//! (and, for tests, an injected [`fake::FakeNativeStore`]). Production KEK
//! placement is the OS keyring on first-run when the probe is available,
//! otherwise a `private_fs` file. dest=database is rejected while the probe
//! is available. Tests never touch real OS keyrings or mutate
//! the process-global default store.
//!
//! Consumer ciphertext tables integrate via transaction-scoped hooks
//! [`activate_ref_in_tx`] / [`begin_release_in_tx`] on the same connection.

mod actor;
mod consumer;
mod error;
pub mod fake;
mod kek_store;
mod key_material;
mod manifest;
mod migrate;
mod namespace;
mod native_store;
mod platform;
mod resolve;
mod sealed_ops;
mod sealed_state;
mod vault;
mod vault_store;
mod worker;

pub use sealed_state::{
    MAX_PAYLOAD_LEN, SealedHealth, SealedPayload, SealedSlot, SealedStateMeta, SealedStateView,
};

#[cfg(test)]
mod sealed_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod vault_tests;

pub use actor::{SECURE_KEY_QUEUE_CAPACITY, SecureKeyActor, SecureKeyHandle};
pub use consumer::{
    ConsumerReconciler, FailClosedReconciler, MapReconciler, activate_ref_in_tx,
    begin_release_in_tx,
};
pub use error::SecureKeyError;
pub use kek_store::{
    FileKekStore, KekStore, KeyringKekStore, MemoryKekStore, file_kek_supported, kek_file_path,
};
pub use key_material::{KEY_BYTE_LEN, SecureKeyBytes, generate_key_bytes, key_digest};
pub use migrate::{
    VaultFault, VaultFaultPoint, migrate_kek_placement, reject_keyring_if_unavailable,
    resume_kek_migrate,
};
pub use namespace::{
    LEAK_REPORT_V1_NAMESPACE, NAMESPACE_MAX_LEN, Namespace, REDACTION_HISTORY_V1_NAMESPACE,
    SECURE_KEY_SERVICE,
};
pub use resolve::{
    DEFAULT_FIX_COMMAND, EffectiveSecretStore, KekUnavailable, SecretStoreInjected,
    ensure_secret_vault, kek_dir_for_db, migrate_installation_kek, open_for_db,
    project_secret_store_snapshot, resolve_secret_store, vault_for_db,
};

#[cfg(feature = "test-support")]
pub use resolve::{
    TestInjectedVault, test_available_keyring_probe, test_missing_keyring_probe, test_open_db,
};
pub use vault::{SecretVault, redaction_table_item_id, session_sealed_item_id};
pub use vault_store::VaultNativeStore;
// set_default / unset_default are actor-owned only (`pub(crate)` in platform.rs).
pub use platform::{
    KeyringProbeResult, PlatformStoreKind, RegistrationOrderSnapshot, platform_link_token,
    platform_store_kind, probe_platform_keyring, probe_platform_keyring_refresh,
    probe_platform_keyring_with, reachable_native_store_crate, registration_order_snapshot,
    reset_registration_order_for_test, set_test_skip_real_default_store,
};
#[cfg(test)]
pub use platform::{
    default_platform_store_is_registered, keyring_probe_construct_count,
    reset_keyring_probe_cache_for_test,
};
pub use worker::{NamespaceMetadata, VersionMetadata};
