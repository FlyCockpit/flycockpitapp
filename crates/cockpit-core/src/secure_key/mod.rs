//! Daemon-owned versioned native secure key store.
//!
//! One actor thread serializes create/rotate/retire against OS native items
//! and SQLite coordination. Tests inject [`fake::FakeNativeStore`] and never
//! touch real OS keyrings or mutate the process-global default store.
//!
//! Consumer ciphertext tables integrate via transaction-scoped hooks
//! [`activate_ref_in_tx`] / [`begin_release_in_tx`] on the same connection.

mod actor;
mod consumer;
mod error;
pub mod fake;
mod key_material;
mod manifest;
mod namespace;
mod native_store;
mod platform;
mod sealed_ops;
mod sealed_state;
mod worker;

pub use sealed_state::{
    MAX_PAYLOAD_LEN, SealedHealth, SealedPayload, SealedSlot, SealedStateMeta, SealedStateView,
};

#[cfg(test)]
mod sealed_tests;
#[cfg(test)]
mod tests;

pub use actor::{SECURE_KEY_QUEUE_CAPACITY, SecureKeyActor, SecureKeyHandle};
pub use consumer::{
    ConsumerReconciler, FailClosedReconciler, MapReconciler, activate_ref_in_tx,
    begin_release_in_tx,
};
pub use error::SecureKeyError;
pub use key_material::{KEY_BYTE_LEN, SecureKeyBytes, generate_key_bytes, key_digest};
pub use namespace::{
    LEAK_REPORT_V1_NAMESPACE, NAMESPACE_MAX_LEN, Namespace, REDACTION_HISTORY_V1_NAMESPACE,
    SECURE_KEY_SERVICE,
};
// set_default / unset_default are actor-owned only (`pub(crate)` in platform.rs).
pub use platform::{
    PlatformStoreKind, RegistrationOrderSnapshot, platform_link_token, platform_store_kind,
    reachable_native_store_crate, registration_order_snapshot, reset_registration_order_for_test,
    set_test_skip_real_default_store,
};
pub use worker::{NamespaceMetadata, VersionMetadata};
