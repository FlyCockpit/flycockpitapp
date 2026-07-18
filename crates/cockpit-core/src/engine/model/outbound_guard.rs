use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;

use crate::redact::RedactionTable;

/// Shared outbound-text safety guard for provider-bound requests.
///
/// This is the single owner of the live trusted-only dispatch gate and the
/// outbound redaction chokepoint. Callers still decide where their
/// non-safety gates belong (for example daemon-drain checks), but every
/// provider-bound text path uses this type for the security invariants.
#[derive(Clone)]
pub(crate) struct OutboundGuard {
    provider_id: String,
    model_id: String,
    trusted_only: Arc<AtomicBool>,
    trusted: bool,
    redact: Arc<RedactionTable>,
}

impl OutboundGuard {
    pub(crate) fn new(
        provider_id: impl Into<String>,
        model_id: impl Into<String>,
        trusted_only: Arc<AtomicBool>,
        trusted: bool,
        redact: Arc<RedactionTable>,
    ) -> Self {
        Self {
            provider_id: provider_id.into(),
            model_id: model_id.into(),
            trusted_only,
            trusted,
            redact,
        }
    }

    pub(crate) fn ensure_dispatch_allowed(&self) -> Result<()> {
        if self.trusted_only.load(Ordering::Relaxed) && !self.trusted {
            return Err(trusted_only_violation(&self.provider_id, &self.model_id));
        }
        Ok(())
    }

    pub(crate) fn scrub(&self, text: &str) -> String {
        self.redact.scrub(text)
    }

    pub(crate) fn scrub_many(&self, texts: &[&str]) -> Vec<String> {
        texts.iter().map(|text| self.scrub(text)).collect()
    }
}

pub(crate) fn trusted_only_violation(provider_id: &str, model_id: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "trusted-only is enabled; model `{provider_id}:{model_id}` is untrusted. Select a trusted model or run `/trusted-only off`."
    )
}
