use std::sync::Arc;

use crate::redact::RedactionTable;

/// Shared outbound-text redaction chokepoint for provider-bound requests.
#[derive(Clone)]
pub(crate) struct OutboundGuard {
    redact: Arc<RedactionTable>,
}

impl OutboundGuard {
    pub(crate) fn new(redact: Arc<RedactionTable>) -> Self {
        Self { redact }
    }

    pub(crate) fn scrub(&self, text: &str) -> String {
        self.redact.scrub(text)
    }

    pub(crate) fn scrub_many(&self, texts: &[&str]) -> Vec<String> {
        texts.iter().map(|text| self.scrub(text)).collect()
    }

    /// Extend this request guard with the current command-authentication
    /// material from the credential store. A refreshed command result is
    /// persisted before its retry is constructed, so rebuilding the guard at
    /// that boundary keeps provider error diagnostics from echoing the new
    /// bearer token or any command-supplied header value.
    pub(crate) fn with_current_provider_auth_command_values(
        &self,
        store: &crate::credentials::CredentialStore,
    ) -> anyhow::Result<Self> {
        let store = store.reopen()?;
        let mut redact = (*self.redact).clone();
        for (origin, value) in store.provider_auth_command_entries() {
            redact = redact.with_forced_literal(value, origin)?;
        }
        for (origin, value) in store.provider_oauth_descriptor_entries() {
            redact = redact.with_forced_literal(value, origin)?;
        }
        Ok(Self::new(Arc::new(redact)))
    }
}
