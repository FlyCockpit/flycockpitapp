use anyhow::Result;

use crate::credentials::CredentialStore;

pub const CODEX_OAUTH_PROVIDER: &str = "codex-oauth";
pub const GROK_OAUTH_PROVIDER: &str = "grok-oauth";
pub const ACKNOWLEDGEMENT_TEXT: &str = "Using subscription credentials from this third-party client may violate the provider terms of service and may result in account suspension.";

/// Namespace reserved for subscription OAuth acknowledgement records. Generic
/// provider credential RPCs must reject this prefix so rollback cannot confuse
/// an acknowledgement with an ordinary provider record.
pub const PREFIX: &str = "subscription-oauth-ack:";

pub fn acknowledged_in(store: &CredentialStore, provider: &str) -> bool {
    store
        .get(&format!("{PREFIX}{provider}"))
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
}

pub fn record_in(store: &mut CredentialStore, provider: &str) -> Result<()> {
    store.set(format!("{PREFIX}{provider}"), serde_json::Value::Bool(true));
    store.save()
}

#[cfg(any(test, feature = "test-support"))]
#[path = "subscription_ack_test_helpers.rs"]
mod subscription_ack_test_helpers;
#[cfg(any(test, feature = "test-support"))]
pub use subscription_ack_test_helpers::*;
