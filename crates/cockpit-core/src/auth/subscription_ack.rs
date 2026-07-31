use anyhow::Result;

use crate::credentials::CredentialStore;

pub const CODEX_OAUTH_PROVIDER: &str = "codex-oauth";
pub const GROK_OAUTH_PROVIDER: &str = "grok-oauth";
pub const ACKNOWLEDGEMENT_TEXT: &str = "Using subscription credentials from this third-party client may violate the provider terms of service and may result in account suspension.";

const PREFIX: &str = "subscription-oauth-ack:";

pub fn acknowledged(provider: &str) -> Result<bool> {
    Ok(CredentialStore::open_default()?
        .get(&format!("{PREFIX}{provider}"))
        .and_then(|value| value.as_bool())
        .unwrap_or(false))
}

pub fn record(provider: &str) -> Result<()> {
    let mut store = CredentialStore::open_default()?;
    store.set(format!("{PREFIX}{provider}"), serde_json::Value::Bool(true));
    store.save()
}
