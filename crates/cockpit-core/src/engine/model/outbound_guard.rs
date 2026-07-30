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
}
